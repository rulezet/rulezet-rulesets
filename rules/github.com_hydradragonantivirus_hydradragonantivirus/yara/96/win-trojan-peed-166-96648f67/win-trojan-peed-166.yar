rule Win_Trojan_Peed_166
{
strings:
	$a0 = { f8ba73e4ff0089c171325589e58b5d0885db7402ffd3c9c2040081e91132ab006800 }


condition:
	$a0
}