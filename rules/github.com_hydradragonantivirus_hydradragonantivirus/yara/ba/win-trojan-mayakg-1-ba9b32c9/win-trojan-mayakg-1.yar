rule Win_Trojan_MayakG_1
{
strings:
	$a0 = { 3ddafe750ab8efad2ec41e27099dcf5351525756551e0633 }


condition:
	$a0
}