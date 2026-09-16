rule Win_Trojan_Vienna_126
{
strings:
	$a0 = { 5bbf00015750fc8d77faa5a48bf38daf????b82435cd21 }


condition:
	$a0
}