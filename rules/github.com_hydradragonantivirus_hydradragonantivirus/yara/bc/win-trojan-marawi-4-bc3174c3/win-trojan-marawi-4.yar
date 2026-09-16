rule Win_Trojan_Marawi_4
{
strings:
	$a0 = { 8c06400126a12c002ea3220226a10a002ea3200126a10c002ea32201b8ffff50babbbbb430cd215881faaaaa7403eb }


condition:
	$a0
}