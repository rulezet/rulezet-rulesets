rule Win_Trojan_Vgen_150
{
strings:
	$a0 = { 904443b42acd2180fa0174027514b80200b9e703fa99cd26483dffff75f8fbcd19c3b801faba4559cd16eb0e905b }


condition:
	$a0
}