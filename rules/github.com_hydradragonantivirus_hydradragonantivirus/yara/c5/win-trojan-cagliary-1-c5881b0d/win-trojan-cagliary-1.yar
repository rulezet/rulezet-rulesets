rule Win_Trojan_Cagliary_1
{
strings:
	$a0 = { 4559cd16720c81ff59457506b00233dbcd16fcb8abffcd213d4143752581fb4c47751f81f94149751981fa49 }


condition:
	$a0
}