rule Win_Trojan_Crypt_198
{
strings:
	$a0 = { f6c689685a0a0644040068cc0af958f88bc931c09bb9dc400f0083ef00c1c9018d3fc1c3a0bede48ee3d }


condition:
	$a0
}