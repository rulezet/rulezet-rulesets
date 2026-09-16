rule Win_Spyware_6643_1
{
strings:
	$a0 = { 6056be0678b00081ee4733b2ef293424 }


condition:
	$a0
}