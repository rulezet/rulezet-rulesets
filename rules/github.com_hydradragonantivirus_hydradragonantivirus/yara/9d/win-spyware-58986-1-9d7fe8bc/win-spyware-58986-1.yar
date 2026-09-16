rule Win_Spyware_58986_1
{
strings:
	$a0 = { 578bfc83ec30c744241200000000c744240400000000c74424 }

	$a1 = { 732249252b }


condition:
	$a0 and $a1
}