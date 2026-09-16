rule Win_Trojan_KYCC_2
{
strings:
	$a0 = { c0c472ba4801cd21b823d0c1c814ba9d0042cd21935333dbb9f002ba00018bea68009007e8e8005bb420d0c4cd21 }


condition:
	$a0
}