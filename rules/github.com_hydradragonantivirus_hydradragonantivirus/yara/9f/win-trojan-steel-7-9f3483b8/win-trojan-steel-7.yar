rule Win_Trojan_Steel_7
{
strings:
	$a0 = { 312d03002ea364012e803e62010f74228cc88ed8b44033d2b9a101cd2133c933d28bc0b8 }


condition:
	$a0
}