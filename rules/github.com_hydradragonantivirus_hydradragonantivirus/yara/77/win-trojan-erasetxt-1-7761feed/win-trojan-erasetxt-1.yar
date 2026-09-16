rule Win_Trojan_EraseTxt_1
{
strings:
	$a0 = { b44e33c9ba2e01cd217222b8023dba9e00cd2172188bd8b440b90900ba3401cd21b44fcd217206ebe2b43ecd21c3 }


condition:
	$a0
}