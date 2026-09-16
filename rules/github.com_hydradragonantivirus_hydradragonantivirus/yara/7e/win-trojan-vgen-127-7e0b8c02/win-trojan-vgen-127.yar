rule Win_Trojan_VGEN_127
{
strings:
	$a0 = { 8b2d81ed0b018db60401b90400b8ff004097fcf3a4b41a8d962702cd21c686260200b44e8db64502c68620022a }


condition:
	$a0
}