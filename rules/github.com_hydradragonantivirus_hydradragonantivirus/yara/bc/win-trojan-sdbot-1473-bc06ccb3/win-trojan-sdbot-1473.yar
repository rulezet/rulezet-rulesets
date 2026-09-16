rule Win_Trojan_SdBot_1473
{
strings:
	$a0 = { 643374420e80853b01c07364626f743a30359b2e6318cba7378069 }


condition:
	$a0
}