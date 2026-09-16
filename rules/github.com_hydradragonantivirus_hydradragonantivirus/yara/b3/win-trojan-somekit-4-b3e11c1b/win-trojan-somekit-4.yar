rule Win_Trojan_SomeKit_4
{
strings:
	$a0 = { 01fab8455992929292929292929292e80000cc5d81ed16012efe863d012e80be450100741e0e0e071f8db647018bfe }


condition:
	$a0
}