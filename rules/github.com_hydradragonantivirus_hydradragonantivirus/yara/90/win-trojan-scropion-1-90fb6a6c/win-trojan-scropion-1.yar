rule Win_Trojan_Scropion_1
{
strings:
	$a0 = { 60085302595e5f9a2f075302595e5f9a29075302b982cdbeccccbfcc4c9a290753028946fa895e }


condition:
	$a0
}