rule Win_Trojan_DOS_5
{
strings:
	$a0 = { 1e57b8ff00509afd083000bfa8010e57b83f0050bf52021e579a42002400833e7e0300752e }


condition:
	$a0
}