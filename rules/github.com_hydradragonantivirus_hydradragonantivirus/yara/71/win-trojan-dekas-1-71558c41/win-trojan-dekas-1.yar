rule Win_Trojan_Dekas_1
{
strings:
	$a0 = { ae005589e5b800019acd02ae0081ec00019aff0cae00bf38061e57bf76030e579a9a04ae00bf38061e57b80100 }


condition:
	$a0
}