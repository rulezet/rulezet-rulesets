rule Win_Trojan_VGEN_19
{
strings:
	$a0 = { 0e8cc801063801bab70103c28bd8054b028edb8ec033f633ffb90800f3a54b484a79ee8ec38ed8be4a00ad8be8 }


condition:
	$a0
}