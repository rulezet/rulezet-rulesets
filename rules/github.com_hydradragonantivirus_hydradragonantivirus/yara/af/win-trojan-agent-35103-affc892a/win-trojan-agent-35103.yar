rule Win_Trojan_Agent_35103
{
strings:
	$a0 = { bd50e1889f313a458ec30917ff0265aff91a9e77d6a0f2e523b8554d8dd5029a3474d3bc059a417d6b6534ce7e9db8da3322d452fac3a98bfc545534 }


condition:
	$a0
}