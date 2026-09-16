rule Win_Trojan_Small_141
{
strings:
	$a0 = { 568bfeb0218ec0b17af3a48ed9be840026380d750ba5a5b425061fba2e01cd210e0e1f07bee8045fb17af3a4c35080 }


condition:
	$a0
}