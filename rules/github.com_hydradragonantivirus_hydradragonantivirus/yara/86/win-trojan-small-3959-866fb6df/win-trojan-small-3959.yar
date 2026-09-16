rule Win_Trojan_Small_3959
{
strings:
	$a0 = { 31d25252bab8174900ff1209c0752a89c281c2cbacf2f381c23565560c }


condition:
	$a0
}