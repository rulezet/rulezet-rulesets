rule Win_Spyware_Banker_3026
{
strings:
	$a0 = { 760bc1f4b64c57446fde301818ed1061e6aa4a07b169efcd51c7d868dcddcfe3e640e160c627f2cb421c7b0bbc }


condition:
	$a0
}