rule Win_Downloader_70138_1
{
strings:
	$a0 = { 782e6f70656e22676574 }

	$a1 = { 7074683d22633a5c6c6f61646b33322e657865 }

	$a2 = { 61736362286d6964622863732c692b }


condition:
	$a0 and $a1 and $a2
}