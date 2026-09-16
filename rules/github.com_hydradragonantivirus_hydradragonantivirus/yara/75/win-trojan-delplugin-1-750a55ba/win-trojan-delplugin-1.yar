rule Win_Trojan_DelPlugin_1
{
strings:
	$a0 = { 64656c20633a5c6172717569767e315c??62??6c7567696e }


condition:
	$a0
}