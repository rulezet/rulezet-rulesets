rule Win_Trojan_Demon_2
{
strings:
	$a0 = { b201b44eb90b11cd21907302eb11e84900ba8000b44fcd21907302eb02ebefb42acd213c027404b44ccd21c606be010090eb0190a0bf01b9a000ba0000bb00 }


condition:
	$a0
}