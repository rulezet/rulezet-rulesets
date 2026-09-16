rule Win_Trojan_Julia_1
{
strings:
	$a0 = { 51521e065657fae8800383eb0dbe1801b9ec008bc62e30004ee2f8fbb4f0cd2180fc807475b462cd214b2ba0ec }


condition:
	$a0
}