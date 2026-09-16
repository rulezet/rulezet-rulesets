rule Win_Trojan_Conzouler_2
{
strings:
	$a0 = { 0300cd2090b87742cd217334b44abbffffcd21b44a83eb1c90cd21b448bb1b00cd212d10008ec0bf03018bf48b3483 }


condition:
	$a0
}