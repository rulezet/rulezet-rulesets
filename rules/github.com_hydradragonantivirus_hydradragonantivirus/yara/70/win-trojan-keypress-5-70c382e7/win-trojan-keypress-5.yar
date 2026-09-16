rule Win_Trojan_KeyPress_5
{
strings:
	$a0 = { f6061e0101750bb440b91000ba0001cd21c3b440b91800ba3901cd21c3b80042cd21c333c9 }


condition:
	$a0
}