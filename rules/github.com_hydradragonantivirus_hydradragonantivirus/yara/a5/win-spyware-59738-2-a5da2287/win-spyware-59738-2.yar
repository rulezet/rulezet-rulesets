rule Win_Spyware_59738_2
{
strings:
	$a0 = { 558bec83e4f883ec185356be4801000056e8 }

	$a1 = { 42656e646572446c6c2e646c6c }


condition:
	$a0 and $a1
}