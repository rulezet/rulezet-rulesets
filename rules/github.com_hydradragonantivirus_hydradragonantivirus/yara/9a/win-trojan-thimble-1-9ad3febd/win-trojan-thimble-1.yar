rule Win_Trojan_Thimble_1
{
strings:
	$a0 = { b021cd21b0eaa20002891e01028c060302b425b0ff }


condition:
	$a0
}