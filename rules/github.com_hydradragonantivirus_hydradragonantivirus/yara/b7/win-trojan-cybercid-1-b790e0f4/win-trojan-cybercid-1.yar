rule Win_Trojan_Cybercid_1
{
strings:
	$a0 = { 212d0300a32406b440ba00018b0ec305cd21b8004233d233c9cd21b440b90300ba2306cd21 }


condition:
	$a0
}