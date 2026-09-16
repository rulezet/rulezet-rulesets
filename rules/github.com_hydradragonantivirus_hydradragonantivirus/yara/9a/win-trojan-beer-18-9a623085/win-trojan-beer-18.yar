rule Win_Trojan_Beer_18
{
strings:
	$a0 = { e4fe8b1e8c038b168e03b442b00033c9e8d3feb440b98803ba03012bca010e8e038b1e8c03 }


condition:
	$a0
}