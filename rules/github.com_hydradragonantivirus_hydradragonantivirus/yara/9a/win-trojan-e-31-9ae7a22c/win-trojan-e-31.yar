rule Win_Trojan_E_31
{
strings:
	$a0 = { 0dcd21b8024abb7601cd2f477505b001eb67904f893efe0157be0001b97601f3a45fb870008ed8beb40081c7f300a5 }


condition:
	$a0
}