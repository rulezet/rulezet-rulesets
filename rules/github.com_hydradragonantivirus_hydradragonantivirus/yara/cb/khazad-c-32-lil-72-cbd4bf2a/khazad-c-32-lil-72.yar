rule khazad_c__32_lil_72_
{
strings:
	$a0 = { 742f54ba4dd2d353bf8dac504c9a5270d197d5eaa65b513399a848defcb732db9b919ee36e41bbe2956bcba502b1f3a1141dc4cc5dda63c3cd7ddc5f5c6c5a7fedff26f78e6f9de8 }

condition:
	$a0
}