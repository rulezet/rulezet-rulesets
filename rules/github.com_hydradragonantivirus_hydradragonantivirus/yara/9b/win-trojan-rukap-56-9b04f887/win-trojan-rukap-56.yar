rule Win_Trojan_Rukap_56
{
strings:
	$a0 = { 9e95f64e329f2ccd3ff30784b7d3b8cda940c046ff9bfca28dc6655a88ba55b9b2262c154587b6294275d8b7c1d77aff8453c8d1aa90c5a62c4194dda3dcd99f9c50eaf6b5faae70 }


condition:
	$a0
}