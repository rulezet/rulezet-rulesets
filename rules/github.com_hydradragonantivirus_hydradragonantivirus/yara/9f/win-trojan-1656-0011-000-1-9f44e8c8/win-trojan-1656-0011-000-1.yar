rule Win_Trojan__1656_0011_000_1
{
strings:
	$a0 = { 0bbef705b9d804ba0301e89501b440cd21075fb440b91c00badb05cd21e86c01b440b91a00 }


condition:
	$a0
}