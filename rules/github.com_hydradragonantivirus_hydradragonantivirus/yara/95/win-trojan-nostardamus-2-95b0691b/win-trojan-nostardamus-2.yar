rule Win_Trojan_Nostardamus_2
{
strings:
	$a0 = { b1f366d1c54e0bcb22f366cfc5941516177dc51c92e645a6e445becf1f1e1d3acc46af51cd489ec5 }


condition:
	$a0
}