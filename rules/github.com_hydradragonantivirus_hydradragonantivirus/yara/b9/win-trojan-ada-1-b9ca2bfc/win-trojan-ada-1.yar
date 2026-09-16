rule Win_Trojan_Ada_1
{
strings:
	$a0 = { 740f80fc41741b80fc1374163d004b74069d2eff2e }


condition:
	$a0
}