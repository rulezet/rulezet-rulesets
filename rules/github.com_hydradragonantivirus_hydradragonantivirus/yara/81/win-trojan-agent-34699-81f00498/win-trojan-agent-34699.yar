rule Win_Trojan_Agent_34699
{
strings:
	$a0 = { e83bffffff05277f0000ffe0e82fffffff05b3760000ffe0e804000000ffffffff5ec30074cf30749343bf5c }


condition:
	$a0
}