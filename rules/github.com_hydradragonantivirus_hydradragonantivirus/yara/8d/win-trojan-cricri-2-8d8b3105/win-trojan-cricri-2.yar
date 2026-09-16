rule Win_Trojan_CriCri_2
{
strings:
	$a0 = { 8be6fb832e13040990a11304b106d3e08ec033c0cd13b90000b600b8090233dbcd13720306 }


condition:
	$a0
}