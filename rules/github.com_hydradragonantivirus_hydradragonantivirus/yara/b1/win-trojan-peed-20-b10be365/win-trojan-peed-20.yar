rule Win_Trojan_Peed_20
{
strings:
	$a0 = { 29db81ebe04d40006800020000f7db8b0418ffd052682a33 }


condition:
	$a0
}