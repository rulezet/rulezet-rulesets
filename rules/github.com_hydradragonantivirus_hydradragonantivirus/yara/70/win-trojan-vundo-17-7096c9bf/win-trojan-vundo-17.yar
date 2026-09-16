rule Win_Trojan_Vundo_17
{
strings:
	$a0 = { 565058e8b5130000a4e8e91700002a7607e216d9 }


condition:
	$a0
}