rule Win_Trojan_Les_1
{
strings:
	$a0 = { 46e74d756180be47e75a755a8dbe7aff165731c031d252509a2806a2008dbe7aff1657bf5200 }


condition:
	$a0
}