rule Win_Trojan_Malmsey_4
{
strings:
	$a0 = { 834f4c4e4d49480119221f546b11180040414546444782f5 }


condition:
	$a0
}