rule Win_Trojan_Fivem_1
{
strings:
	$a0 = { f302b70050558becc7460200405d58cd218b0eec028b16ee0233db8a1ef302b80157cd215055 }


condition:
	$a0
}