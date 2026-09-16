rule Win_Trojan_VGEN_60
{
strings:
	$a0 = { 83ee03b90100b600b809028bde81c30002b200cd1372f1b809038bde81c30000b201cd13fec680fe0275ddb600fec5 }


condition:
	$a0
}