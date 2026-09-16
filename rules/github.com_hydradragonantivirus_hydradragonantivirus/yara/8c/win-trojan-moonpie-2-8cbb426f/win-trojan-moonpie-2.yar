rule Win_Trojan_MoonPie_2
{
strings:
	$a0 = { 8abb5e0175542fc510a318a43d2df5f53f74037468705f30cb3b03f04e11f66347641f842d3c8b192ac50ab0c240ba317d810c9b6049ca69334aedb8187fe50b }


condition:
	$a0
}