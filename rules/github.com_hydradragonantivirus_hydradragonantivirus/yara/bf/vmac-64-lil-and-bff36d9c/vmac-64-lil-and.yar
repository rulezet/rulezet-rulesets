rule VMAC__64_lil_AND_
{
strings:
	$a0 = { fffeffffffffffff[0-20]ffffffffffffff3f[0-20]ffffffffffffff7f[0-20]ffffffffffffffff[0-20]ffffff1fffffff1f }

condition:
	$a0
}