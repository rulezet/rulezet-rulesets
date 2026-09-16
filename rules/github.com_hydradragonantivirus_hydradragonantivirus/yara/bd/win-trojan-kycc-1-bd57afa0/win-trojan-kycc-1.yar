rule Win_Trojan_KYCC_1
{
strings:
	$a0 = { 81ef0801575f8b854c02a30001575e8b844e02a30201565f8a855002a20401b419fec48d95c601cd21b44ec0c4802b }


condition:
	$a0
}