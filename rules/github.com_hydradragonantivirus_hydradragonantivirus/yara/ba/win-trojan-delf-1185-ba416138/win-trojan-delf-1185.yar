rule Win_Trojan_Delf_1185
{
strings:
	$a0 = { 5964891068ad4500108d45ece813ebffffc3e9a9e5ffffebf05f5e5be813eaffff000000 }


condition:
	$a0
}