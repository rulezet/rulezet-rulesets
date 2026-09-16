rule Win_Trojan_Australian_15
{
strings:
	$a0 = { 8db6f001bf000157a5a4b8a054cd213d0612743f1e58488ec08b1e020081eb1500891e020026812e0300150083 }


condition:
	$a0
}