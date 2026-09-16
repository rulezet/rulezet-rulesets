rule Win_Trojan_SillyOC_19
{
strings:
	$a0 = { f1f10081f1f100cd21b428b440b9b900ba0800ba0001cd21b43e0543002d4300cd2181f2b50081 }


condition:
	$a0
}