rule Win_Trojan_Solar_2
{
strings:
	$a0 = { e0042bc8874c102e890e2200619c2eff1e6600601eb4400e1f99b96600cd211f61ca0200 }


condition:
	$a0
}