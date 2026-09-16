rule Win_Trojan_HWF_4
{
strings:
	$a0 = { bb22000e72001fb989f35185e181c10210589090280785c348fa43fce2f6 }


condition:
	$a0
}