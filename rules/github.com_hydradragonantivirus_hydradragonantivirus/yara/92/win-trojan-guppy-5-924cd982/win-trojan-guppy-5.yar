rule Win_Trojan_Guppy_5
{
strings:
	$a0 = { 21358bd8cd21899c95008c84970089 }


condition:
	$a0
}