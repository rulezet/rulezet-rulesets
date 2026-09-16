rule Win_Trojan_Sigh_1
{
strings:
	$a0 = { ce592616d42415a82b37daafee93 }

	$a1 = { 7caf1830b0c44a36ee61008f72c1b589bfdb58d02cd22fd49dec }

	$a2 = { d0969040594d98c10809971280c65e4336537b2506bd253c02302563a030f23a32db1fc6e92b97ac7731 }


condition:
	$a0 and $a1 and $a2
}