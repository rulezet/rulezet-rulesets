rule Win_Trojan_NYB_1
{
strings:
	$a0 = { ba8000be130433ff8edfff0cad5eb106d3e08ec02bf35650b8ae01500e560e1fe8aeff8ed9 }


condition:
	$a0
}