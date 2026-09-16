rule Win_Trojan_Dragon1_1
{
strings:
	$a0 = { 8be0be4c00ada3657cada3677c8b1613044a89161304b106d3e28ec2b895010650be007c33ff }


condition:
	$a0
}