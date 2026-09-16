rule Win_Trojan_NYB_2
{
strings:
	$a0 = { ba8000be130433ff8edfff0cad5eb106d3e08ec02bf35650b8ad01500e560e1fe86d008ed9 }


condition:
	$a0
}