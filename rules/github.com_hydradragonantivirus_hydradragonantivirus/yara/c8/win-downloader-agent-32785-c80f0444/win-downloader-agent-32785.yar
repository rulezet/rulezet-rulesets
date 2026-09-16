rule Win_Downloader_Agent_32785
{
strings:
	$a0 = { dc9f0dde0599b4ca5db17047815cfc29c3c987b255b6bac8d5871812eecdc8683be49f2095c97880cd6e11066dcf1d38177deb06f8c0cb27bacec90946e1fa39e11f3a84452d40940d0d14 }


condition:
	$a0
}