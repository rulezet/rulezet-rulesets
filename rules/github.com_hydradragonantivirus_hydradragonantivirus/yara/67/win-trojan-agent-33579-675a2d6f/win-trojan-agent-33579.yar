rule Win_Trojan_Agent_33579
{
strings:
	$a0 = { bd2a03d48affb5ae8015307c3072338991ce34f3dea099660786af751c9e374b9b4f71840cc3cbde798ace2bb0caf146d43a93cc0270ccbfe3415adefd90c58e862d82e4e116ee1a011c56786d7345a41bef }


condition:
	$a0
}