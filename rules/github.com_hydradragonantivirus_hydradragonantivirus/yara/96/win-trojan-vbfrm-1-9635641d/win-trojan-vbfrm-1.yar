rule Win_Trojan_VbFrm_1
{
strings:
	$a0 = { 302d433030302d00000000ffcc3100007fe2515bd7f88b4bae0ff9cd221b4b13042edadbf2e49b4ebfc30c1b386f7ebb3a4fad339966cf11b70c00aa0060d393 }


condition:
	$a0
}