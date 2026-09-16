rule Win_Trojan_B_93
{
strings:
	$a0 = { 8b16130083ea0289161300b930008ed183f136d3e233dbb801028be38ec2b1018af5b200cd13 }


condition:
	$a0
}