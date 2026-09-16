rule Win_Trojan_Small_2625
{
strings:
	$a0 = { 55545d6affff35a8943b3eff2548953b3e50ffd68d95f8feffffb102e877f70000ff2528953b3e89f9e898f70000e9a5010000 }


condition:
	$a0
}