rule Win_Trojan_Bancos_1890
{
strings:
	$a0 = { becdcf2165c1321847ddee8243e806dcd516686d3f1929239f9c20128ddd2cbd74418aab7f7c5693466a0005520326b5c2ccdb6ea54f737f38f689ea82b57c7b6a784ee0cb26 }


condition:
	$a0
}