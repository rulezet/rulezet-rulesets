rule Win_Trojan_VLADBios_1
{
strings:
	$a0 = { b80102b9010033d2bb2603cd13b80103b90e00b601cd13b80103b90100b600bb2601cd13cd20be007c33c08ec0fa8ed08be6fb8ed8ff0e1304cd12b106d3e08e }


condition:
	$a0
}