rule Win_Trojan_SdBot_3690
{
strings:
	$a0 = { 26316da8832e3872924ba129e6b3dd1b2f580fc78aa042a2002e43eec95bc05e9f38a5b3cc30427155dadfaa79c0fa96896d016a6adbd1b2c156b21dcb883754114c40b14b1f1ff8cdce7833db4d }


condition:
	$a0
}