rule Win_Trojan_Yanush_3
{
strings:
	$a0 = { 080160061e55fab83412508bec58fb3b46007504ebf9ffff5de81600e80500e83502eb23538b94a9048d9c5201 }


condition:
	$a0
}