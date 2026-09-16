rule Win_Trojan_Agent_33048
{
strings:
	$a0 = { 6a0068409040008bcde824fcffff6a006840904000ff15bc8040008b4424105f5e5d5b83c444c3 }


condition:
	$a0
}