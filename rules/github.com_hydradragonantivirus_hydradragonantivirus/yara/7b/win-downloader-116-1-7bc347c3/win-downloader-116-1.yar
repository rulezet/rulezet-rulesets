rule Win_Downloader_116_1
{
strings:
	$a0 = { 6d3fa4a53d4869596abae3816c30f02f83a2f4706d3fa4a52982292d6fbae430f8ffe090cb15adf4c245d0b259fbed306d0d3a88a0959d686fbae4632d48a1f263bae3b90a7bda306dae8fbce2c26d8e6521 }


condition:
	$a0
}