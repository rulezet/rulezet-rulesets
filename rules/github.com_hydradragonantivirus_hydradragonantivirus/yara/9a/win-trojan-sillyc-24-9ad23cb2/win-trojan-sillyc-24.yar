rule Win_Trojan_SillyC_24
{
strings:
	$a0 = { ecc7460200425d58e80c00b43ecd21b44febb457f3a4c352998bcacd215a95b440b1729090cd21 }


condition:
	$a0
}