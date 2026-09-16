rule Win_Trojan_MSShellcode_1
{
strings:
	$a0 = { fc6aeb47e8f9ffffff6031db8b7d3c8b7c3d7801ef8b572001ea8b349a01ee31c099acc1ca0d01c284c075f6436639ca }


condition:
	$a0
}