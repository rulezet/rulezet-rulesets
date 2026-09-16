rule Win_Trojan_Mybot_7251
{
strings:
	$a0 = { d653dffe2e8c4b88b437df6608da896a7bed6a5e63087de8634e6ca9f78d1b3f6a01cbd0050006af97fed45f6968a8d2eb8d1e1b35dabab51d5f24b03a312ecf853358393c92d489f18148226afc }


condition:
	$a0
}