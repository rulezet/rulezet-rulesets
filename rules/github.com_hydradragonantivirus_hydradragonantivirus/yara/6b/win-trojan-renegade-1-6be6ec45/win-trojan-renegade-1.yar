rule Win_Trojan_Renegade_1
{
strings:
	$a0 = { 0b009cfa2eff1e8004e80100c39c518d0e7f048d3651002bce2e8b3e4f002e313c46e2fa59 }


condition:
	$a0
}