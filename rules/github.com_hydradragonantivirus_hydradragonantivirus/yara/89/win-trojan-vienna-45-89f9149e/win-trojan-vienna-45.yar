rule Win_Trojan_Vienna_45
{
strings:
	$a0 = { b97a02908bd681eaeb01cd21721f }


condition:
	$a0
}