rule Win_Trojan_Cybercid_2
{
strings:
	$a0 = { ddcd213d333d75058d567cffe2b82135cd21899e8e028c869002b80935cd21 }


condition:
	$a0
}