rule Erlang__32_lil_AND_
{
strings:
	$a0 = { b979379e[0-20]72f36e3c[0-20]2b6da6da[0-20]e4e6dd78[0-20]9d601517[0-20]56da4cb5[0-20]0f548453[0-20]c8cdbbf1[0-20]8147f38f[0-20]3ac12a2e[0-20]f33a62cc[0-20]acb4996a[0-20]652ed108[0-20]1ea808a7[0-20]d7214045 }

condition:
	$a0
}