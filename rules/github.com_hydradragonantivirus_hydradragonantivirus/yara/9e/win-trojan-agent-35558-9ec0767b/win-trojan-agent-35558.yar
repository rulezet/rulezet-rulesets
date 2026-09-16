rule Win_Trojan_Agent_35558
{
strings:
	$a0 = { 5589e583ec146a02ff1564614000e8bdfeffff8db6 }

	$a1 = { 656a67677767650067666a717738717738386771 }


condition:
	$a0 and $a1
}