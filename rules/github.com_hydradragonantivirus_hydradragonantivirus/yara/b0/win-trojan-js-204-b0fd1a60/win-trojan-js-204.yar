rule Win_Trojan_JS_204
{
strings:
	$a0 = { c3e2c9b1b5c4617370 }

	$a1 = { 73657373696f6e285c225c226361697a6875 }

	$a2 = { 6e6f32322e6173705c }

	$a3 = { 7265645c223e6c7563696665723c2f }


condition:
	$a0 and $a1 and $a2 and $a3
}