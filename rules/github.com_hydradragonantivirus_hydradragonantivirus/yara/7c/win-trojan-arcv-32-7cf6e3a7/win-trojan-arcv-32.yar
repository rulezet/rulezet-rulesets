rule Win_Trojan_ARCV_32
{
strings:
	$a0 = { 01b9bd012e812c000083c6024975f5 }


condition:
	$a0
}