rule Win_Trojan_Small_4164
{
strings:
	$a0 = { 3fe8630f89df89dd8dbfbc0700 }


condition:
	$a0
}