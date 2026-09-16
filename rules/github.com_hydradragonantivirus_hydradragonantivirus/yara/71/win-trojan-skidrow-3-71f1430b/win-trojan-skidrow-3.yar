rule Win_Trojan_SkidRow_3
{
strings:
	$a0 = { cd21b452cd2126c57712c5341e1e584050fcb902008b }


condition:
	$a0
}