rule Win_Trojan_Killav_178
{
strings:
	$a0 = { 64656c74726565202f7920633a5c70726f6772617e315c616e746976697e315c }

	$a1 = { 7279207374726f6e67 }


condition:
	$a0 and $a1
}