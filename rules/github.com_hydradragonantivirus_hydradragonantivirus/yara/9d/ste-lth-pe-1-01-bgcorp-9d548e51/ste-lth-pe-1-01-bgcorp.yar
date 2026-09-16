rule Ste_lth_PE_1_01____BGCorp
{
strings:
		$a0 = { BA ?? ?? ?? 00  }

condition:
		$a0 at entrypoint
}