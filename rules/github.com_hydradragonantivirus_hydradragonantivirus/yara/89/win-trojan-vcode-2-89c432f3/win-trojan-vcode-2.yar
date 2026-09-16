rule Win_Trojan_VCode_2
{
strings:
	$a0 = { cd2180fe06751b2ec606240000a02400b9240031d242bb9000cd262efe062400ebebc39c068c }


condition:
	$a0
}