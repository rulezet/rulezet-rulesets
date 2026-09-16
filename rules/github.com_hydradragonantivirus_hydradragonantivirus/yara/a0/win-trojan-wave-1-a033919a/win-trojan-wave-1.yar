rule Win_Trojan_Wave_1
{
strings:
	$a0 = { 0190b44ccd215157561e52b80043cd7872215180e1feb8003dcd788bd81e52b80044cd7880e21f80fa025a1f7d0b }


condition:
	$a0
}