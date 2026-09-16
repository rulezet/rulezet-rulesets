rule Win_Trojan_Solar_3
{
strings:
	$a0 = { 288b4404034412c1e0042bc8874c102e890e2300619c2eff1d601eb4400e1f998bcf9cff1d }


condition:
	$a0
}