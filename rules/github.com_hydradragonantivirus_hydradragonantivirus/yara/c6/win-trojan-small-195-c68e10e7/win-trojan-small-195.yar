rule Win_Trojan_Small_195
{
strings:
	$a0 = { 5c00be0201bf3203fda7fc0e56f3a4ea17003300740f56be84005626a526a55f8cc8abab5e5f571e078bcc2bcff3a4cb80fc3c752350cde39358721cb8 }


condition:
	$a0
}