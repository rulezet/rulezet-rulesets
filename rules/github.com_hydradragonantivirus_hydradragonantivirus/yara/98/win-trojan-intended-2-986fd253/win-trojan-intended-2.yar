rule Win_Trojan_Intended_2
{
strings:
	$a0 = { e80000cc5d81ed0202b82435cd210653b82425ba1a02cd21e90400b80300cfb8efbecd213defbe7451b44abbffffcd21 }


condition:
	$a0
}