rule Win_Trojan_W_419
{
strings:
	$a0 = { 2e4164642822633a5c736f6c76657465632e646f636d22 }


condition:
	$a0
}