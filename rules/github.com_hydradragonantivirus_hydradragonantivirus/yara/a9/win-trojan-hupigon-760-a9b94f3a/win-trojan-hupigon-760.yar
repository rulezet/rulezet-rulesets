rule Win_Trojan_Hupigon_760
{
strings:
	$a0 = { 6b18851de23ec83bde8f418d8bdd0f3858a7679acd17a622e1f4407abad30e3e5a8b8acdaae0b6b6cb4e8328bacd64cc9f9e6775d074023da86b7cb416c1dfc18323befadd7302c3f0c8319f7d1e }


condition:
	$a0
}