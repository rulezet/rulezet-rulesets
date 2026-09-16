rule Win_Trojan_Junior_1
{
strings:
	$a0 = { 4d5a743a803cc4743531c98bd1b80242cd21462d36003b047424b1e001c850b440b602cd218f }


condition:
	$a0
}