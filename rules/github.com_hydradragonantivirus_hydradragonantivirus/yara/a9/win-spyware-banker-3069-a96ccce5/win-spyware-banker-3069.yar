rule Win_Spyware_Banker_3069
{
strings:
	$a0 = { 54f35899e4c98173ff651d3bffc00372fcadf5ac4d48bae285d1c4a4a32eb4f5b34b03a1dd858312727182bc2134ba803251 }


condition:
	$a0
}