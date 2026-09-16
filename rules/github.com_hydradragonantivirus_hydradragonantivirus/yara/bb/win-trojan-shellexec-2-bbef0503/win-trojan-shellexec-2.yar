rule Win_Trojan_ShellExec_2
{
strings:
	$a0 = { 24616374696f6e20213d20227370616d3122 }

	$a1 = { 213d22627275745f66747022 }

	$a2 = { 213d2022646f776e6c6f61645f6d61696c22 }


condition:
	$a0 and $a1 and $a2
}