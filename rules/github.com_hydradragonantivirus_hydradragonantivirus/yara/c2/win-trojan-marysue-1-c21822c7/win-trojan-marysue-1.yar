rule Win_Trojan_MarySue_1
{
strings:
	$a0 = { e800005e81ee0a018bac1b0281c50201eb1789842202b4408d940501b91a01cd219c9d7201c3e98d }


condition:
	$a0
}