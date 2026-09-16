rule Win_Trojan_Cmnd_2
{
strings:
	$a0 = { 181e579abc09ec01bf83181e57ff360b199a2400ce015dc30120052a2e657865052a2e636f6d }


condition:
	$a0
}