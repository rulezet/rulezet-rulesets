rule Win_Trojan_Nova_1
{
strings:
	$a0 = { 09bafa010500003b060200721bb409ba1801cd21cd204e6f7420656e6f756768206d656d6f7279242d20008ed02d }


condition:
	$a0
}