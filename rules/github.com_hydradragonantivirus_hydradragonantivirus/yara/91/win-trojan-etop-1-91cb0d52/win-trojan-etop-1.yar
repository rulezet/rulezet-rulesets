rule Win_Trojan_Etop_1
{
strings:
	$a0 = { 582d17018be881fc3639740ebfe5008db6d60183c71b57a4eb121e060e1f0e078dbed5018d }


condition:
	$a0
}