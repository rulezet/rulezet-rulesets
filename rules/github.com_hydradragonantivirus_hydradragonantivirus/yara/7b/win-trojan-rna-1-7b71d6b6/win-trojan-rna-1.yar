rule Win_Trojan_RNA_1
{
strings:
	$a0 = { 57c43ef6010657b8002050bfff011e579ab10bb700bfae }


condition:
	$a0
}