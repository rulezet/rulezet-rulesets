rule DMC_compression__32_big_AND_
{
strings:
	$a0 = { 3e4ccccd[0-20]3e4ccccd[0-20]3e4ccccd[0-20]3e4ccccd }

condition:
	$a0
}