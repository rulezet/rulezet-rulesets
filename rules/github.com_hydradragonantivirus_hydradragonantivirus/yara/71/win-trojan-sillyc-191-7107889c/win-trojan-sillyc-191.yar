rule Win_Trojan_SillyC_191
{
strings:
	$a0 = { 21b002e83800b440b97c018d960401cd21eb198d966f02b43bcd217219e978ffb43ecd21e83700 }


condition:
	$a0
}