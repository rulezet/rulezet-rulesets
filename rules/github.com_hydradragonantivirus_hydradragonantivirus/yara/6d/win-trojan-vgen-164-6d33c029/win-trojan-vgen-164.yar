rule Win_Trojan_VGEN_164
{
strings:
	$a0 = { cd213c027302cd20bf71108b3602002bf781fe00107203be0010fa8ed781c41e14fb730c33c036c7066a121802e9 }


condition:
	$a0
}