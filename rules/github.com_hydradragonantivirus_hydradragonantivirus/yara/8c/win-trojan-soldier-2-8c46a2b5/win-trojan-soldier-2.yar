rule Win_Trojan_Soldier_2
{
strings:
	$a0 = { 3e42054d5a7502eb1c833ee60200755fa1e4022d0500a36105b440b90500ba5e05cd21eb4a }


condition:
	$a0
}