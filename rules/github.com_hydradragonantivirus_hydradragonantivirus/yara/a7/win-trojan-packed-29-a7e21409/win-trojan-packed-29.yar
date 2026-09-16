rule Win_Trojan_Packed_29
{
strings:
	$a0 = { 4d5a4b45524e454c33322e444c4c }

	$a1 = { ffff7011111443fbcccc4fffffff04ccccc4ffffffffffffffff70111111443bbcccc4fffff04cccccc4ffffffffffffffff7011111144c3fbcccc4fff04ccccccc4ffffffffffffffff70111111144c3bbcccc4444ccccccc4fffffffffffffffff70111111114cc33bbccccccccccc }


condition:
	$a0 and $a1
}