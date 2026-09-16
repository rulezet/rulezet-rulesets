rule Win_Trojan_Yard_1
{
strings:
	$a0 = { ee198beefcb8ababcd213dbaba751bbf0001578bf5a5a5a4c35850488ec0268b5f0383eb2107b44acd2106b452cd }


condition:
	$a0
}