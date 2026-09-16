rule Win_Trojan_SdBot_3661
{
strings:
	$a0 = { e3fd0500a6f56a3f95a725d8f29d5780c058a3cf6d570fded854c0c9ded2076d1a9eac5b81faac1cdac7e8499b9fd7e985a38ed1da31685da4e1289d12717f074dce777b38a0efc81378024d2a03 }


condition:
	$a0
}