rule Win_Spyware_Sinowal_22
{
strings:
	$a0 = { 5f6675636b416c6c50726f636573736573403800 }


condition:
	$a0
}