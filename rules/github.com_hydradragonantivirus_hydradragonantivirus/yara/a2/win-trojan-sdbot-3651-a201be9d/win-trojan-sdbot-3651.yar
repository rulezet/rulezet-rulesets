rule Win_Trojan_SdBot_3651
{
strings:
	$a0 = { 175b80fa3850060d4a5852e86abf5a25f363d00a39ce7251d5b1ba6b24ec4cccea2fddcdab115dcd36f7bb2f8ca3a380d181c823cc113cc2a7c2defad4f5cf3041528a34b599c5342412088bd101 }


condition:
	$a0
}