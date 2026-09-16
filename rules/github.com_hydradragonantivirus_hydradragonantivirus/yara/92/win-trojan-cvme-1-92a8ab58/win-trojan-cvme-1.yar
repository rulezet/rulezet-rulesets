rule Win_Trojan_CVME_1
{
strings:
	$a0 = { 9fa9b873136c0d448146c418895ec40152f013c47f59861ccfe5f200441860178fb539c49549dc01 }


condition:
	$a0
}