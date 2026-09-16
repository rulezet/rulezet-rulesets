rule Win_Trojan_VGEN_536
{
strings:
	$a0 = { dc00cd2000566f4663418db60601bf000157b90300fcf3a4b447b2008db64602cd213ec68645025c3ec6861a02038d }


condition:
	$a0
}