rule Win_Trojan_Flame_1
{
strings:
	$a0 = { b80103b601b103807f15fd7403b90e00890e0b02cd60720db80103bb0002b9010032f6cd605f }


condition:
	$a0
}