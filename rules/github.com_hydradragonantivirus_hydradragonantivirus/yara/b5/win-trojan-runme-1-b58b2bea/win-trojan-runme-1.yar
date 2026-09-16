rule Win_Trojan_Runme_1
{
strings:
	$a0 = { bf9e051e57bf1e071e57ff361e47bf20471e579aca077500bf9e051e579a590775005dc355 }


condition:
	$a0
}