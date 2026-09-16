rule Win_Trojan_N_40
{
strings:
	$a0 = { 8ed3bc007c8ec4fbb91828ba0000fc36803e87007b7411bf03002ae4cd13b80502cd13730b4f75f2be8e7ce807 }


condition:
	$a0
}