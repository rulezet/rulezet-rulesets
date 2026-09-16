rule Win_Trojan_Bancos_1012
{
strings:
	$a0 = { 7d11bb50110821ca2fb8f7ee4d36720f47cf17cd067a80e55cfbea7815775dd39cc5b36bd3d17cf7f69391e033bbb065964f64052cc50cfde795aa8828a4c4ed4f7a661c807add929b159e5a2455bb8ab0f9 }


condition:
	$a0
}