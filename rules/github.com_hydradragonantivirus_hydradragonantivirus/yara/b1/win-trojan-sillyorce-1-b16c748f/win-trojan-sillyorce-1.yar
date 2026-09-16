rule Win_Trojan_SillyORCE_1
{
strings:
	$a0 = { 2135cd21891e65018c066701ba1801b425cd21b29acd2780fc4b75479053515706501e }


condition:
	$a0
}