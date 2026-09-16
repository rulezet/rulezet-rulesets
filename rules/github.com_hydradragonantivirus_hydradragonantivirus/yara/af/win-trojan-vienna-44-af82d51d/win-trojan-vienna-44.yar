rule Win_Trojan_Vienna_44
{
strings:
	$a0 = { 8b4c049081e1e0ff81c91f00b80157 }


condition:
	$a0
}