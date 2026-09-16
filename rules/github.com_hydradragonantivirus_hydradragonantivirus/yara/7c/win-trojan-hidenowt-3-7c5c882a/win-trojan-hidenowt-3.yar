rule Win_Trojan_Hidenowt_3
{
strings:
	$a0 = { 9200c3b003cfbab807b43de82400a30701c333c933d2b442eb14b43feb10b440e80b007201c3 }


condition:
	$a0
}