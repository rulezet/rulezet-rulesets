rule Win_Spyware_5747_1
{
strings:
	$a0 = { 83bdc4feffff000f85430100006a006a02e8920500008985d0feffff0bc00f842c010000c785d8feffff280100008d85d8feffff50ffb5d0feffffe8c2050000e9f8000000 }


condition:
	$a0
}