rule Win_Trojan_Baby_L_1
{
strings:
	$a0 = { 83ee039c50535152571e06b42acd2180fa0c75251e0e1fbb01008d946b02b92900b440cd2133c05033db8bd3b93200 }


condition:
	$a0
}