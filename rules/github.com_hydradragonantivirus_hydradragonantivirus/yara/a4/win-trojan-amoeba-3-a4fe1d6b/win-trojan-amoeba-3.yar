rule Win_Trojan_Amoeba_3
{
strings:
	$a0 = { cd7503e9c900be02008b042dc000 }


condition:
	$a0
}