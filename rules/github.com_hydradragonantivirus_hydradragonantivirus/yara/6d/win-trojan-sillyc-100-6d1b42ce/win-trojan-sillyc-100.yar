rule Win_Trojan_SillyC_100
{
strings:
	$a0 = { 42cd213d2fff73d3508bd5b9d000b440cd2133c933d2b80042cd218bf581c6cc00c604e9582d }


condition:
	$a0
}