rule Win_Trojan_Awake_4
{
strings:
	$a0 = { 20e8000087fe5d87f78d761e90e80200eb108a965202b934028bfeac32c2aae2fa }


condition:
	$a0
}