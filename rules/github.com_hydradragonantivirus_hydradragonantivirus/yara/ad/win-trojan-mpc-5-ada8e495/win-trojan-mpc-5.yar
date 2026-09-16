rule Win_Trojan_MPC_5
{
strings:
	$a0 = { 5d81ed16018db69e01bf000157a5a4b41a8d96b502cd21b82435cd21899eb1028c86b302b4 }


condition:
	$a0
}