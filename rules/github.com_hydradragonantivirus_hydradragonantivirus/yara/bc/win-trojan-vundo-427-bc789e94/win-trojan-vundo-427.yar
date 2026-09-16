rule Win_Trojan_Vundo_427
{
strings:
	$a0 = { 50eb104e4348484b4d40454a434a4e464e4149e9ed0400005790e98b010000d3c881c8100f86 }


condition:
	$a0
}