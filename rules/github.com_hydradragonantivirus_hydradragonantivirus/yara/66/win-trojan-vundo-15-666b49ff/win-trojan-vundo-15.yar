rule Win_Trojan_Vundo_15
{
strings:
	$a0 = { 5690e8e11e00002b0fbbb7000066f2e5e85617 }


condition:
	$a0
}