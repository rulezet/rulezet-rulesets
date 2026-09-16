rule Win_Trojan_Vova_3
{
strings:
	$a0 = { 40007402eb07833e48250975a9bf82050e57b8100050bfb0241e579ae2004301833e6c4000 }


condition:
	$a0
}