rule Win_Trojan_Bedep_2
{
strings:
	$a0 = { ff154040001056536a03535368901f0000ff7508ff7604ff1554410010894608 }


condition:
	$a0
}