rule Win_Trojan_Depent_1
{
strings:
	$a0 = { 5d81ed14018bf581c638018bdd81c30d018b57028b1f89f7fcb91701ad01d82bdaabe2f8 }


condition:
	$a0
}