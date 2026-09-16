rule Win_Trojan_1992_1
{
strings:
	$a0 = { e9e60051bb??018a2f322e0301882f4381fb??047ef159c3ba0001 }

	$a1 = { b440cd2153 }


condition:
	$a0 and $a1
}