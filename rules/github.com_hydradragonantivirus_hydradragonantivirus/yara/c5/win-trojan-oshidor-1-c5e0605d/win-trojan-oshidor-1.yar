rule Win_Trojan_Oshidor_1
{
strings:
	$a0 = { e866bf478540ac9604788f97519651d8784285eda6fd838ae867a42a0d6ae035dc4fc69cbb591af0239324 }


condition:
	$a0
}