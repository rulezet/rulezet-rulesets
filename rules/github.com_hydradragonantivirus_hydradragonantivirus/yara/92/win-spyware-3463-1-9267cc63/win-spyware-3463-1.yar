rule Win_Spyware_3463_1
{
strings:
	$a0 = { 8c50d3c858ba99de2ac156be13f700005ec350538bc78bde5b58b90000000052 }


condition:
	$a0
}