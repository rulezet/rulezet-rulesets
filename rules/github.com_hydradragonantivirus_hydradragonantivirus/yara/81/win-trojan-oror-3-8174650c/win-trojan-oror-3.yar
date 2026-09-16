rule Win_Trojan_Oror_3
{
strings:
	$a0 = { 495243 }

	$a1 = { 56697275 }

	$a2 = { 53455859330f5455 }

	$a3 = { 4b617a61 }

	$a4 = { 536e617073686f }


condition:
	$a0 and $a1 and $a2 and $a3 and $a4
}