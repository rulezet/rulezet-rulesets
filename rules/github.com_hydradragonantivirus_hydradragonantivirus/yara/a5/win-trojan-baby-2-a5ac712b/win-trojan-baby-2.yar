rule Win_Trojan_Baby_2
{
strings:
	$a0 = { cd21891e52018c065401b425ba1801cd21b287cd2780fc4b753460061ebf5600578bf20e07acaa0ac075fab456 }


condition:
	$a0
}