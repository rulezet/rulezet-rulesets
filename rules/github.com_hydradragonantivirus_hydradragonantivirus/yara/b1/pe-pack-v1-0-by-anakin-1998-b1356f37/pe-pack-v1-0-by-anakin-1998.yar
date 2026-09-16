rule PE_PACK_v1_0_by_ANAKiN_1998______
{
strings:
		$a0 = { 74 ?? E9 ?? ?? ?? ?? 00 00 00 00  }

condition:
		$a0 at entrypoint
}