rule Win_Trojan_Downloader_149
{
strings:
	$a0 = { 35337a373472696e7a363728293b7a37647a3362223b66 }

	$a1 = { 2872293b7d6576616c287a2824612929 }


condition:
	$a0 and $a1
}