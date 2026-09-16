rule Win_Trojan_Stoned_30
{
strings:
	$a0 = { 1872dcbebe03bfbe01b94200f3a4b8010333db41cd18ebc7b80102bb007ccd18c38b45118b5d16 }


condition:
	$a0
}