rule Win_Trojan_Vienna_91
{
strings:
	$a0 = { c177038bfe81ef7502890db440b9af03908bd681ea7702cd21 }


condition:
	$a0
}