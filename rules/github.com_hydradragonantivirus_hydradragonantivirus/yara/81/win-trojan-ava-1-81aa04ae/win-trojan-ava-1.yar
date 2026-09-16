rule Win_Trojan_Ava_1
{
strings:
	$a0 = { cd213ddcfe7405e8180090908cc88ed82b062100a3250007ff2e23001400230100008cc88ed88cc0488ec0bb }


condition:
	$a0
}