rule Win_Trojan_Bancos_1900
{
strings:
	$a0 = { 9e783de5c74eccad78d3efff06549a0fd9edf2862e8147bd7d07838acbb94483e33676d0ec72fd36f6bd1578167e196f22396444bc329da017d01241dfe8e65e78334bd4bbf6 }


condition:
	$a0
}