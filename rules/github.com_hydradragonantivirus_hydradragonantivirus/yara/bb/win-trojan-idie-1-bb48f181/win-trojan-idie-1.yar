rule Win_Trojan_Idie_1
{
strings:
	$a0 = { 1ffa8306860004832e130405fbb106cd12d3e08ec050b80902bb0001b90200ba8000cd13b8fb01500e }


condition:
	$a0
}