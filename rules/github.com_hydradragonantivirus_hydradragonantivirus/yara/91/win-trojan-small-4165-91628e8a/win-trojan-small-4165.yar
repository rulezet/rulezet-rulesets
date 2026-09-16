rule Win_Trojan_Small_4165
{
strings:
	$a0 = { 8d9800????0089dfb851????006a00546a40680010000053ff500489dd8dbfbc }


condition:
	$a0
}