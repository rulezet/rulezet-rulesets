rule Win_Trojan_DarthVader_12
{
strings:
	$a0 = { be00908ec631f64681fe000f77eb5631 }


condition:
	$a0
}