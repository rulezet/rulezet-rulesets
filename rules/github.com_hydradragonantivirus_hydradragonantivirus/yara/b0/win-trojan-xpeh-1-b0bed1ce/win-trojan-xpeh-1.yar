rule Win_Trojan_XPEH_1
{
strings:
	$a0 = { d3eb8bfbbb9600d3ebb8080050b8f00dd3e82bc348 }


condition:
	$a0
}