rule Win_Dropper_Small_3455
{
strings:
	$a0 = { e8d5ebffff8bf08d8d50ffffffbacc321413a190561413e8c2edffff8b9550ffffffb890561413e89ae5ffff6a00689456141353b890561413e88ce8ffff5056e8ddebffff }


condition:
	$a0
}