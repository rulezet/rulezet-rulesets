rule Win_Trojan_W_41
{
strings:
	$a0 = { 2bc9bf001000c0b8ff000000b9fffffffff2ae8bd90bc90f8480000000 }


condition:
	$a0
}