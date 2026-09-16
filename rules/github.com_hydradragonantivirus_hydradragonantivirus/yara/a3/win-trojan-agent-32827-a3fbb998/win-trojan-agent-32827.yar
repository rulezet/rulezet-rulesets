rule Win_Trojan_Agent_32827
{
strings:
	$a0 = { fa64390f9cc3ba90f6a9a6cf3353082a8fd62a475d215f14ff838e15a09c56e3a8a96f826b3f2494e46f167ec1db3e6bef3ac009797750cf89faf3f9a48ce07ce1 }


condition:
	$a0
}