rule Win_Trojan_Tricks_4
{
strings:
	$a0 = { ee0301ffb4b601ffb4b801e87400b44e8d94b00133c9cd107259b8023dba9e00cd108bd8b43f8d94b601b90400cd }


condition:
	$a0
}