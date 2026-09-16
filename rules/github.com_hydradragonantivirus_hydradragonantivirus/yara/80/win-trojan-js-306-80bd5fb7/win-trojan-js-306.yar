rule Win_Trojan_JS_306
{
strings:
	$a0 = { 6161613d222f746573742f69223b }

	$a1 = { 3b6e3d5b342e352c342e352c35322e }

	$a2 = { 282d682a6e5b6a5d293b7d6528737329 }


condition:
	$a0 and $a1 and $a2
}