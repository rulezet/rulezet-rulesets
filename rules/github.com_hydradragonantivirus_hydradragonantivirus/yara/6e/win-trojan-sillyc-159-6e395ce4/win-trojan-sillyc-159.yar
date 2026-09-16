rule Win_Trojan_SillyC_159
{
strings:
	$a0 = { a3130158250f00b910002bc85803c150b440cd21582d0300a32f021e33c08ed8a06c041f }


condition:
	$a0
}