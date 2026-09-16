rule Win_Trojan_Bancos_643
{
strings:
	$a0 = { 71c577ee06ca5239e4b2ba79026f4bcd19ce21b6ba32289cb9c490446e6ece4fa29178f718cd96dcff89073b186e8fec3f6bc8af4bcb3abbd92995146214c61ef025d5056c35806a83dd56f6c95cd297 }


condition:
	$a0
}