rule Win_Trojan_Monster_22
{
strings:
	$a0 = { 02bede2cfc300446e2fb25cdcd934e23ce2572cc00ed0b89dc3326cd0b89dccd2544cc4649facf6ecdcc4749 }


condition:
	$a0
}