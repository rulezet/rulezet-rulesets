rule Win_Trojan_Andreas_1
{
strings:
	$a0 = { e92ea30501e81f018d160401b90300b440cd21721b33d22e89161c01e81201e8de0059b43ecd21 }


condition:
	$a0
}