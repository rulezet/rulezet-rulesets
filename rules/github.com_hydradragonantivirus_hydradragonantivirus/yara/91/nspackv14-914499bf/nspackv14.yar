import "pe"
rule NsPackV14 : LiuXingPing
{
	meta:
		author="malware-lu"
strings:
		$a0 = { 9C 60 E8 00 00 00 00 5D B8 B1 85 40 00 2D AA 85 40 00 }

condition:
		$a0 at pe.entry_point
}