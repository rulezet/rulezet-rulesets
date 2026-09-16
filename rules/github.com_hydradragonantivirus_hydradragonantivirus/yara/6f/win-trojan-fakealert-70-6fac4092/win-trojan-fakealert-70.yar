rule Win_Trojan_Fakealert_70
{
strings:
	$a0 = { ffffffffffffffffffff7c7cffd9d9fffffffff8f8ffd0d0ff }


condition:
	$a0
}