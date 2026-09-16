rule Win_Trojan_Mybot_188
{
strings:
	$a0 = { 1e03626561676ca2312542750a2e0118b90a08531d9168c501723c3216f50ef06d7964516fe84d }


condition:
	$a0
}