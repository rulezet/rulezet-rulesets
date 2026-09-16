rule Win_Trojan__0023_0005_001_1
{
strings:
	$a0 = { 50558becc7460200405d58ba9a10b91310cd21bf4a08b0e9aa58abb06baab80042505833c933d2 }


condition:
	$a0
}