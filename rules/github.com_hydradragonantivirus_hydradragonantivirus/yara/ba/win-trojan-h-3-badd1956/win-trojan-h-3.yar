rule Win_Trojan_H_3
{
strings:
	$a0 = { 07b8004acd217324075b1f58eb8939 }


condition:
	$a0
}