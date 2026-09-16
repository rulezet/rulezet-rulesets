rule Win_Trojan_Vgen_151
{
strings:
	$a0 = { 125b4869446f735d004279204170616368650033c08ed8fa8ed0bc007cfba14e00a3aa7da14c00a3a87da113044848 }


condition:
	$a0
}