rule Win_Trojan_Small_3957
{
strings:
	$a0 = { 31d25252bab8??4000ff1209c0752a89c281c2cb??eaf381c23565560c8d8a3c050000520577d7afb12902ff0a31c083c20283c20239ca7eebbad6??4000ff12c3 }


condition:
	$a0
}