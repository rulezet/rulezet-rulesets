rule Win_Trojan_SillyRC_2
{
strings:
	$a0 = { 8bfe56b82135cd2133c98cc58ec126803cbe74191e8ed9891e8003892e8203b425ba4301cde01ffcb97d00f3a4 }


condition:
	$a0
}