rule Win_Trojan_Agent_33084
{
strings:
	$a0 = { bd414eefcf3b2e3c3bc30bfb4fbdd7712b371b05e486a5ba1faeb2cdf269b6988e6cfc49a50bc44caafb32f38f78c431d13b9e7fc4c090858a546e3d1d5a47ce3d88a88b2a67f3af6c3775 }


condition:
	$a0
}