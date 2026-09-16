rule Win_Downloader_Agent_32879
{
strings:
	$a0 = { fc93ab0dbd9c3eed21f06d00739012622b9d137388e666bf69f85d867b95c41ecc79c73760de89c13709ad0e6f33f8c3454a30d5ed1bfc1e2f310103e431 }


condition:
	$a0
}