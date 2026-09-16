rule Win_Trojan_Magistr_10
{
strings:
	$a0 = { fce804720000391dd5bb04a4b324377205f21e90907e0d2e0bcdf4ec60f9ebc8d22036b4eca964c711070cf67577eb48869e925a8abe11dc00636816fdbe67d4ccebce628b3dc90fc273bd2ac6a927d50e23 }


condition:
	$a0
}