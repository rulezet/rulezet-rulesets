rule Win_Trojan_OneHalf_3
{
strings:
	$a0 = { f4981d29337f0630f21a95d74236e19bc2a4053b71110d85c992a9b23fa63b393d572ecda502c529ed86b868b406f53d }


condition:
	$a0
}