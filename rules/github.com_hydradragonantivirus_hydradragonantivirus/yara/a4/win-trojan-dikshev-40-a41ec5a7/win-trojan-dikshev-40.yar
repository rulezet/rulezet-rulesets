rule Win_Trojan_Dikshev_40
{
strings:
	$a0 = { de8c4f04061e071fcd21c38bd7b82e5bf2ae66c705636f6d008bcecd2193b44f72b8b440eb }


condition:
	$a0
}