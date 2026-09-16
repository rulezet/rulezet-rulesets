rule Win_Trojan_Australian_17
{
strings:
	$a0 = { b6f101bf000157a4a5b8a054cd213d0212743f8cd8488ec08b1e020081eb1500891e020026812e0300150083 }


condition:
	$a0
}