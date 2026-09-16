rule Win_Trojan_NightFall_4
{
strings:
	$a0 = { 0c026bdcacae8a5f2b60bcd72390934acf2c869120a1e1dfd57373f5ae8821b223fc3873c832245d87a26b4c17961b308e495659 }


condition:
	$a0
}