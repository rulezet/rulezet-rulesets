rule Win_Trojan_Lmir_136
{
strings:
	$a0 = { e6b5c3a14d6346e7b9c6ad639ce41cd0c03f39a15ce67c409dd6e1e6bb47c8423b981c26b90b23988dc5098bb4356243ed08b5fbe6f5b6958d1e5cdfc462da7d2e356de4e0259abc39b758afac88f60c }


condition:
	$a0
}