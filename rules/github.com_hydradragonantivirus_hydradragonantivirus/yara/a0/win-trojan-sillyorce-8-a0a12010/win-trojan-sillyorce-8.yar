rule Win_Trojan_SillyORCE_8
{
strings:
	$a0 = { 515706501eb43cb100cd210e1f93b440b94300ba0001cd21b43ecd211f58075f595bcf5eea }


condition:
	$a0
}