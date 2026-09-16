rule Win_Trojan_Proxy_80
{
strings:
	$a0 = { 006079000fefee7d0076002bdf81eef06ab9f653bbb4df87d25b7d000f58df8b15182f4100be17abe45e81d14e81da338d05 }


condition:
	$a0
}