rule Win_Trojan_CmosDense_1
{
strings:
	$a0 = { 0e1ffa83eb03bf00018db72303b90200f3a51f0eb80001501eeb1ee80100905b81eb24002e8b9721038cc0051000 }


condition:
	$a0
}