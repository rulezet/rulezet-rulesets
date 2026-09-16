rule Win_Trojan_Packed_14
{
strings:
	$a0 = { 5bb82f1304502df210045003c38130d2[0-200]5e1c03dd8b048b03c5ab5e59c3e83bffffff6881c9ab86686587c15a33c06578 }


condition:
	$a0
}