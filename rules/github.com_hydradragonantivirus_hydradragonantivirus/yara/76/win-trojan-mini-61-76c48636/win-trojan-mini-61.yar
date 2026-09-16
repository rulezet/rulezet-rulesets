rule Win_Trojan_Mini_61
{
strings:
	$a0 = { 3dba9e00cd2193b43fba4b0189e1cd21054b00502bc9f7e1b442cd2159b4405a52cd21b44feb }


condition:
	$a0
}