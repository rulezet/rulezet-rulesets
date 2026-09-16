rule Win_Trojan_Mini_12
{
strings:
	$a0 = { cd2193061fb43f575a33c95149cd21056700905950b8004299cd21b44059565acd210e1fb43e }


condition:
	$a0
}