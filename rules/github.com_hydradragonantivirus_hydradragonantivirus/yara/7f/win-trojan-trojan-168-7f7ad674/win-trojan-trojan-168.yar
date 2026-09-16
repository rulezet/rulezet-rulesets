rule Win_Trojan_Trojan_168
{
strings:
	$a0 = { f6e88b000bc0740ae8510046fe06f002eb08ba8b03b43bcd21463b36ed027ce1803ef00200740ab8ba0250e8360159eb27803eef0206761833f6eb0d8bde }


condition:
	$a0
}