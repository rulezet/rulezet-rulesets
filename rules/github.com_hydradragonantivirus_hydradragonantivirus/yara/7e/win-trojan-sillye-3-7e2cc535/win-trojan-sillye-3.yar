rule Win_Trojan_SillyE_3
{
strings:
	$a0 = { b440b937018d960001cd21e85e0050b109d3e8d3caf913d05880e4018986060289960802b0 }


condition:
	$a0
}