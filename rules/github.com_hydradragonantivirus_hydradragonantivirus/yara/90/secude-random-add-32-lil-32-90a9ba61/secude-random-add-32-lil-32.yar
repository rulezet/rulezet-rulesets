rule SecuDE_random_add__32_lil_32_
{
strings:
	$a0 = { 13115723232119174137312959534743aebc6f4567bd6f45ddbc5f2467355643 }

condition:
	$a0
}