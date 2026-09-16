rule Win_Trojan_Ldpinch_29
{
strings:
	$a0 = { 83ec000fca4981ee0817000081f98354292a8bc981ff98554d }

	$a1 = { 3e36203a1b4137 }


condition:
	$a0 and $a1
}