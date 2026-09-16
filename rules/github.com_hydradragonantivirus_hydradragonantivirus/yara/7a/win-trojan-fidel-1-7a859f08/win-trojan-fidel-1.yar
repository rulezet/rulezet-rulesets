rule Win_Trojan_Fidel_1
{
strings:
	$a0 = { 8cc80510008ed850b8????50cb }

	$a1 = { b43cb0eba30000b4f6b93801be01018a0432c48804463bf175f5 }


condition:
	$a0 and $a1
}