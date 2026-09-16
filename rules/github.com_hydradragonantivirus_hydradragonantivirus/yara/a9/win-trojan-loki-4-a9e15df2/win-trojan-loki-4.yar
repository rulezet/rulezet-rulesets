rule Win_Trojan_Loki_4
{
strings:
	$a0 = { 1000f7e1f88bcf81c10b0503c183d200f82be81bda }


condition:
	$a0
}