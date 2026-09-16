rule Win_Trojan_Gummy_2
{
strings:
	$a0 = { 04468b042d04008904b106d3e05007545e33ffb90002f3a406b8590050cbbb00022e8b0e1e00 }


condition:
	$a0
}