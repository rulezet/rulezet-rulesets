rule Win_Trojan_DarthVader_2
{
strings:
	$a0 = { 5b83eb06a3fe0031c08ed8c406ac0031ffb90010e84f0072392e89bf930031f6061fad3d2e8b74034eebf7ac3c9f74034eebf5ad938b8f800093 }


condition:
	$a0
}