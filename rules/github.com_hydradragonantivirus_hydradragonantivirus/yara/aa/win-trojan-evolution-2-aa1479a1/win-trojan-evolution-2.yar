rule Win_Trojan_Evolution_2
{
strings:
	$a0 = { 0e1f682a005e8cc88ec08d0ed402fc668b0483c6046635d39eaecb66890583c70083c704e2 }


condition:
	$a0
}