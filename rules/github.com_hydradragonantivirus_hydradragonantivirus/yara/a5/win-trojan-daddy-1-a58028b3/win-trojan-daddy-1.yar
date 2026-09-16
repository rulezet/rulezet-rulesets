rule Win_Trojan_Daddy_1
{
strings:
	$a0 = { 89e58b760083ee0333edc351b9????d0c8f6d82e300446e2f659c3 }


condition:
	$a0
}