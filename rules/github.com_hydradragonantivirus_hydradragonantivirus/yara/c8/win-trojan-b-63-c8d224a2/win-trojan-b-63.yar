rule Win_Trojan_B_63
{
strings:
	$a0 = { 8ed8bd007cfa8ed08be5fb5055a11304ff364e00ff }


condition:
	$a0
}