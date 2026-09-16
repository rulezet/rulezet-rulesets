rule Win_Trojan_VGEN_487
{
strings:
	$a0 = { 02000e1fe44024030ac00f858d00b80300cd10fc33dbe878000a0d070a0d070a0d075b4f55 }


condition:
	$a0
}