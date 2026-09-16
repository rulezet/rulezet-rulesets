rule Win_Trojan_Morgot_1
{
strings:
	$a0 = { c70602048500c3b9f90390ba00008b1e1e04b440e962feb91c00baf8038b1e1e04b440e953fe }


condition:
	$a0
}