rule Win_Trojan_Lupita_1
{
strings:
	$a0 = { 010100550000000000ffff9c0600002d020000040000009c06 }


condition:
	$a0
}