rule Win_Trojan_Andris_2
{
strings:
	$a0 = { 53807710de90b9f20383c31f908a07343a880743e2f7 }


condition:
	$a0
}