rule Win_Spyware_Banker_2133
{
strings:
	$a0 = { ec86d7c09fe9c2054320933417dce47ee19c7715c216359fb0d2a2816c6c8bd2eb0132b7ca1a2a327370286bfc0274172337eec4e4c420ecdc5ff1d35ab592d6defd17e0d630b2a01c12f7100dfe }


condition:
	$a0
}