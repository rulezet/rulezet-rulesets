rule Win_Trojan_CorporateLife_3
{
strings:
	$a0 = { 4b90064b4b900e909043431ffbfbfbb8110790bf3e014b4b9043803582fb434b47904875f5904b9043fb9090434b }


condition:
	$a0
}