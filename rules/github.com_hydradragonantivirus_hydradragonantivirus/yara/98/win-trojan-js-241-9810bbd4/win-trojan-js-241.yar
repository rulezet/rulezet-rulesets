rule Win_Trojan_JS_241
{
strings:
	$a0 = { 72226f70656e }

	$a1 = { 616477617265616e6473707977617265 }

	$a2 = { 7363726970745f656e2e6a73 }

	$a3 = { 2f32322f3f7569643d6b6579696e }


condition:
	$a0 and $a1 and $a2 and $a3
}