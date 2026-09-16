rule Win_Trojan_VGEN_726
{
strings:
	$a0 = { 8bea8be88bef8beef7ddf7d57f007400f7d5f7dd8bff7200f7d590cebfb505f7dd8bffcccc8bf6f7dd8bef8bff4d }


condition:
	$a0
}