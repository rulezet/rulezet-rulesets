rule Win_Trojan_Radyum_1
{
strings:
	$a0 = { 1c008d968203e81500b801578b8e6d038b966f03cd218086eb0501e906ffb440cd21c35b44 }


condition:
	$a0
}