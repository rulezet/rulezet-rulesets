rule Win_Trojan_Scraze_1
{
strings:
	$a0 = { baacff4900e8a783f6ff8b85a0feffff508b0d342a4a008b098d859cfeffffbac8ff4900e8cc83f6ff8b859cfeffff33c95ae85aa7fdffe9840400 }

	$a1 = { fbffe80e40f6ff0000ffffffff0b00000053637265656e426c61 }


condition:
	$a0 and $a1
}