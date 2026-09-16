rule Win_Trojan_Dina_2
{
strings:
	$a0 = { ba0001b9ec01b440cd21b43ecd212ec606130100cb9c2e803e130100752853505b80ff4b7403 }


condition:
	$a0
}