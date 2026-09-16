rule Win_Trojan_Mini1_2
{
strings:
	$a0 = { c026a06c040e07a29c02e86c005a5983c91fb80157cd21b43ecd21803e440103742bfe0644 }


condition:
	$a0
}