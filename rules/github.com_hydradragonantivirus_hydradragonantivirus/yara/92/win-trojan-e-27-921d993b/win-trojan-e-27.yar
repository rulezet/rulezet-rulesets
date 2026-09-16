rule Win_Trojan_E_27
{
strings:
	$a0 = { ba161292268a1dcd2f5bb50226086d02b440ba8903cd21b80157268b4d0d268b550fe866005a }


condition:
	$a0
}