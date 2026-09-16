rule Win_Trojan_ShellExec_3
{
strings:
	$a0 = { 24706f72747363616e2c24706f72745f61646472657332 }

	$a1 = { 246174746163683d246669 }

	$a2 = { 6861636b7275 }


condition:
	$a0 and $a1 and $a2
}