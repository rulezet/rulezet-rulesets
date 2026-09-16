rule Win_Trojan_Shish_1
{
strings:
	$a0 = { 03b91800ba63039c0e2eff36d802eb6490da02b442b0028b1e6103b90000ba00009c0e2eff36f2 }


condition:
	$a0
}