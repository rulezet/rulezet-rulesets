rule Win_Trojan_Smut_1
{
strings:
	$a0 = { 1e7d8c4402be2000bf1a7d56a5a55ec704fb7c8c4402cbb80103b90100ba8000bb007ccd13c3 }


condition:
	$a0
}