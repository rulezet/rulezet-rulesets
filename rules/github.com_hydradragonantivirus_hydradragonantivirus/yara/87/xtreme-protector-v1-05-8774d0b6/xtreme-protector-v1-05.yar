rule Xtreme_Protector_v1_05
{
strings:
		$a0 = { E9 ?? ?? 00 00 00 00 00 00 00 00  }

condition:
		$a0 at entrypoint
}