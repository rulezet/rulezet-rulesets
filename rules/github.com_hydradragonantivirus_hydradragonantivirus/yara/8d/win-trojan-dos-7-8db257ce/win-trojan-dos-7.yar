rule Win_Trojan_DOS_7
{
strings:
	$a0 = { 2121b9f107bee00f89f71ea9b5808cc80505008ed805b0018ec0fdf3a5fc2e806c121073e792 }


condition:
	$a0
}