rule Win_Spyware_Banker_5461
{
strings:
	$a0 = { 54113658f686507ceea38fceccb0b63f8881cdd919e513da534399cc2e8880dd71b401e0cfda928d6a5a0d858bd6c61e545a158e0070ea6eac2d66b1190d88cbf94c55fe89393269ebdd0e261eed }


condition:
	$a0
}