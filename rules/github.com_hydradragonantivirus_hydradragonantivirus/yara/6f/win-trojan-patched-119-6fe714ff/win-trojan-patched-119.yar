rule Win_Trojan_Patched_119
{
strings:
	$a0 = { 6068f31f4?00ff15??????0061e9??????ff757365727333322e6461740000 }


condition:
	$a0
}