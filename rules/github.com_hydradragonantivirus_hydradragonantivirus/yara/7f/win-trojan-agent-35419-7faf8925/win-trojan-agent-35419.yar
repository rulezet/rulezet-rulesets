rule Win_Trojan_Agent_35419
{
strings:
	$a0 = { 558bece81854fbffe8030000005dc3cc558bec6afe68e06d }

	$a1 = { 663a5c656b61776563655c65656b75756f5c65 }


condition:
	$a0 and $a1
}