rule Win_Trojan_Cathinone_1
{
strings:
	$a0 = { 960001b9b801cd21b8004233d233c9cd21b4408d96ee02b91c00cd218b8e4b038b964d03b8 }


condition:
	$a0
}