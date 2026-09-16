rule Win_Trojan_SillyC_7
{
strings:
	$a0 = { 5132e4cd1a8896bb01e85900b440b92603ba06012bca8d960601cd217234e84400b801578b8eb9 }


condition:
	$a0
}