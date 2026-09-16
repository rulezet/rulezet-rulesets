rule Win_Trojan_Hell_2
{
strings:
	$a0 = { 014080e7fe8ae7b109d3c8a353035bb8004233c999cd21b440ba4f03b9180090cd21b43ecd21c3 }


condition:
	$a0
}