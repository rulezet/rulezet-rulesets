rule Win_Trojan_Vienna_7
{
strings:
	$a0 = { cd21730be989003e3e372f39333c3cbb005793cd21 }


condition:
	$a0
}