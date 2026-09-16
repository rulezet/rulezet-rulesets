rule NsPackV2X : LiuXingPing
{
	meta:
		author="malware-lu"
strings:
		$a0 = { 6E 73 70 61 63 6B 24 40 }

condition:
		$a0
}