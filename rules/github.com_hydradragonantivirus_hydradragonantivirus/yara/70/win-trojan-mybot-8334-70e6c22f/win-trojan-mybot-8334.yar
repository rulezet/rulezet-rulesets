rule Win_Trojan_Mybot_8334
{
strings:
	$a0 = { 3b29dd31ffa777ba904aaf970de21324fff4a159a4f172c78d265b88297778c5e01bca6d5e2fbe4dcf0208206df946b0da50bf6ff8a6d495fd55aa4b69cd04707ed931a8ef6ec545fea1ffb07d1074f2 }


condition:
	$a0
}