rule Win_Trojan_Tangle_3
{
strings:
	$a0 = { 93b43f8d54fdbf0242b103e815008944f1bf0042b161e80500bf003eb103b4408d54f0cd2197 }


condition:
	$a0
}