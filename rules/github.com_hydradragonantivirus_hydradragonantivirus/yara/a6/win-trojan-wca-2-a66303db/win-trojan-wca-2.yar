rule Win_Trojan_WCA_2
{
strings:
	$a0 = { 3600e84100b440b91301ba0001cd21b801572e8b0e9600 }


condition:
	$a0
}