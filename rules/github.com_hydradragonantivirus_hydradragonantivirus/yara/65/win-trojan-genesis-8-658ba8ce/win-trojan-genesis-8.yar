rule Win_Trojan_Genesis_8
{
strings:
	$a0 = { 40b9f801ba0001cd692e8f06ee02b8004233c933d2cd69b440b90400baf402cd69b43ecd69 }


condition:
	$a0
}