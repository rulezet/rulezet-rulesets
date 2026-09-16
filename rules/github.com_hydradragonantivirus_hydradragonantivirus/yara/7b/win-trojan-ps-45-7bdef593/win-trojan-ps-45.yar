rule Win_Trojan_PS_45
{
strings:
	$a0 = { 28b00281c2920081ea9200e86500b440eb008d96b003eb0059eb00cd2190b82200b8024233c999 }


condition:
	$a0
}