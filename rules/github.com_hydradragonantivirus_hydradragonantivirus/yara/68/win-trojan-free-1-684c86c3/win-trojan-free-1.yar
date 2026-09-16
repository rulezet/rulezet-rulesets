rule Win_Trojan_Free_1
{
strings:
	$a0 = { 09b90a00f3a4ba6e142bfa8bcfb440cd2132c0e85600ba1f09b440b94000cd2166ff361b0959 }


condition:
	$a0
}