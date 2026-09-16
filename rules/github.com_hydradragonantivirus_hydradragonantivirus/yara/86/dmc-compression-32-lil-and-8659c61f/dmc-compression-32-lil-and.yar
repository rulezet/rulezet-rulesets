rule DMC_compression__32_lil_AND_
{
strings:
	$a0 = { cdcc4c3e[0-20]cdcc4c3e[0-20]cdcc4c3e[0-20]cdcc4c3e }

condition:
	$a0
}