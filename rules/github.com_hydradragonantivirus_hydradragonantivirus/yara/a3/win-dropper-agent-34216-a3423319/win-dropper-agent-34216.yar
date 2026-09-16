rule Win_Dropper_Agent_34216
{
strings:
	$a0 = { 558becb9080000006a006a004975f953b818394000e892faffff33c05568863b400064ff30648920 }


condition:
	$a0
}