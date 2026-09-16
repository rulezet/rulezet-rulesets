rule Win_Trojan_MPCn_1
{
strings:
	$a0 = { 408d96820959cd21b8024233c999cd21b4408d960301b90e08cd21b801578b8e6c098b966e09cd }


condition:
	$a0
}