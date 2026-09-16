rule Win_Trojan_Trivial_65
{
strings:
	$a0 = { ba6e01cd213d1200740ee81600b44fcd213d12007402ebf2b409ba7501cd21b44ccd21b43dba800083c21e }


condition:
	$a0
}