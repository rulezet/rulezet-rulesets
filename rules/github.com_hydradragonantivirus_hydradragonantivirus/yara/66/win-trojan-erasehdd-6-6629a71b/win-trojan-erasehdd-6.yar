rule Win_Trojan_EraseHDD_6
{
strings:
	$a0 = { 35cd21891e1d018c061f010e07bb2801b90200ba8000b801039c9a00000000fec675f342ebf0486921 }


condition:
	$a0
}