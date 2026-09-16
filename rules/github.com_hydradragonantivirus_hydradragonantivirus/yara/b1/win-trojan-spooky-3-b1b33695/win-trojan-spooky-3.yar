rule Win_Trojan_Spooky_3
{
strings:
	$a0 = { 023dba9e00cd218bd8b440ba0001b90b00cd21e440240374022c0104013c017511c706ce018ad8 }


condition:
	$a0
}