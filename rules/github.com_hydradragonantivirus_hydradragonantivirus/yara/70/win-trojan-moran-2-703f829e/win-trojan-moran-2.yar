rule Win_Trojan_Moran_2
{
strings:
	$a0 = { 81ed0301fb9cb451cd215333c08ec026c51e0400ff371e53fab84a0103c5fcbf0400ab0e58abfb9c558bec814e0200 }


condition:
	$a0
}