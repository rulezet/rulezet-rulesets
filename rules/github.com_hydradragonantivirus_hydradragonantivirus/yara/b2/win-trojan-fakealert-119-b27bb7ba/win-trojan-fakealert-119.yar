rule Win_Trojan_Fakealert_119
{
strings:
	$a0 = { 60be00e041008dbe0030feff5789e58d }

	$a1 = { 73656375726974796f6e6c696e65726561642e636f6d30343830 }


condition:
	$a0 and $a1
}