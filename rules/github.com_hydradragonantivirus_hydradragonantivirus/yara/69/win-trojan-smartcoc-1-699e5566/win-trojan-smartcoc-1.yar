rule Win_Trojan_Smartcoc_1
{
strings:
	$a0 = { e4cd1a88966301e86700b440b90503ba05012bca8d960501cd217243e85200b801578b8e600180 }


condition:
	$a0
}