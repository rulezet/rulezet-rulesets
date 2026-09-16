rule Win_Trojan_Hupigon_35
{
strings:
	$a0 = { 506a01a154e91413e8dc78ffff8bc8bae0c71413b801000080e82bd9ffff }


condition:
	$a0
}