rule Win_Trojan_K_33
{
strings:
	$a0 = { 0d012e8a848c032e8c84a90350061e0e0e071fffb48803ffb48a03ffb48403ffb48603ffb48d03ffb48f038d94f003 }


condition:
	$a0
}