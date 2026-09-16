rule Win_Trojan_R_36
{
strings:
	$a0 = { 2180fa15740ab409ba2302cd21e91100b409bab701cd21b9e803b8070ecd10e2fce916019c80fc4b7402eb39b8 }


condition:
	$a0
}