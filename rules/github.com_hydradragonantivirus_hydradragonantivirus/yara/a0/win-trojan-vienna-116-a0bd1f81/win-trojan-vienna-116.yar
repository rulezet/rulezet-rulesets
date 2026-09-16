rule Win_Trojan_Vienna_116
{
strings:
	$a0 = { c172038bfe81ef7002890db440b9a603908bd681ea7202cd21 }


condition:
	$a0
}