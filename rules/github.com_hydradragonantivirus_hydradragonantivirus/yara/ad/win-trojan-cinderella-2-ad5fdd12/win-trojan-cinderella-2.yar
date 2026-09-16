rule Win_Trojan_Cinderella_2
{
strings:
	$a0 = { fcfb750432e49dcf80fcfc750e9d1e075fbf0001 }


condition:
	$a0
}