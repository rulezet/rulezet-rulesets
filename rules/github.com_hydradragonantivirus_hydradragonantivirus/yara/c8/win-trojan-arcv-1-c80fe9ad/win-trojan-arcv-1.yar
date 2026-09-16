rule Win_Trojan_Arcv_1
{
strings:
	$a0 = { 5b81eb781681c33012535fb9451581e9311280b531010847b20fe2f6 }


condition:
	$a0
}