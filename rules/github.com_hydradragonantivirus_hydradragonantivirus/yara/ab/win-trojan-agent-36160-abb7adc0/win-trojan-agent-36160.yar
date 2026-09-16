rule Win_Trojan_Agent_36160
{
strings:
	$a0 = { 2e66696c6565786973747328 }

	$a1 = { 2e70617468202620225c }

	$a2 = { 2e766273222c322c7472756529 }


condition:
	$a0 and $a1 and $a2
}