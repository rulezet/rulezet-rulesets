rule Win_Trojan_Vicky_3
{
strings:
	$a0 = { 0900f3a6742933d2b94002b440cd21721eb8004233d233 }


condition:
	$a0
}