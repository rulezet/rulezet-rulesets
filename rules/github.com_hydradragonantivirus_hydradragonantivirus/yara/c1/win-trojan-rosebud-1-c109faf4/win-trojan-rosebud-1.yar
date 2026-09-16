rule Win_Trojan_Rosebud_1
{
strings:
	$a0 = { 7acd213d7698750f2e8e169e012e8b269c012eff2ea0 }


condition:
	$a0
}