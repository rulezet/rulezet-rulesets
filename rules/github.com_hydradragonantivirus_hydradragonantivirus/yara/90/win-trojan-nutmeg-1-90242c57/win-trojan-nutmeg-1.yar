rule Win_Trojan_Nutmeg_1
{
strings:
	$a0 = { 8cc8baf90103d052bad20052bacd0003c28bd80541018edb8ec033f633ffb90800f3a54b484a79ee8ed88ec3be47 }


condition:
	$a0
}