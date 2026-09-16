rule Win_Trojan_Leo_2
{
strings:
	$a0 = { 1e06e800005d8a86f7002ea200018a86f8002ea201018a86f9002ea20201b44ebaf10003d5b92000cd217310e9b9 }


condition:
	$a0
}