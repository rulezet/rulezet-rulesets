rule Win_Spyware_4546_1
{
strings:
	$a0 = { f7d5e90000000047b32132c0 }


condition:
	$a0
}