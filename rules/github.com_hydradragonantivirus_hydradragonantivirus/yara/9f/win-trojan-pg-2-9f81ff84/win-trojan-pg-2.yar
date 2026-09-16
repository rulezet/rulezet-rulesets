rule Win_Trojan_PG_2
{
strings:
	$a0 = { 8ed0bc007c8ed81e16b10650ff0e1304a11304d3e0a3757c8ec0be007c5fb90001fcf3a5ea }


condition:
	$a0
}