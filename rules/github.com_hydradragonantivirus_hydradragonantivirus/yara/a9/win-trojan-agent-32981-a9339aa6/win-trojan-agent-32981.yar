rule Win_Trojan_Agent_32981
{
strings:
	$a0 = { b190554c5c473506735ee7c04fb09d9d686a508afae8c74bd33e764fdd6c2c3aa153b39040b7ea8a264de25da67c7c20e12847bde098ff9dec52dc0fe1df246cf4324373a6a647386c58aab1fd39 }


condition:
	$a0
}