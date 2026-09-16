rule Win_Trojan_Bumaf_1
{
strings:
	$a0 = { 962df4a1fc2d9c4bff479c4bff459c21fcad11a404d363deacc5de15fc2d15e27fd66354e74582bbbd2d7428c92d9c4bfc7df43f666c9cdecac5ba10fc2d775d94220660fcc57215fc2df621ac4593bb }


condition:
	$a0
}