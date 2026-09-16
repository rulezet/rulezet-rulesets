rule Win_Trojan_Trieda_1
{
strings:
	$a0 = { cd213e899eb7023e8c86b9028ec2bac90203d58bf2b41a3e89b6cb00cd21e85101ba6e0103d5 }


condition:
	$a0
}