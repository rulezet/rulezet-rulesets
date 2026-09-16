rule Win_Spyware_1788_1
{
strings:
	$a0 = { 8d4dd4ba0c4c1413a194661413e8bcf1ffff8b55d4b894661413e8d7e7ffff66566657 }


condition:
	$a0
}