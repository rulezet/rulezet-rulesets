rule Win_Trojan_Inject_56
{
strings:
	$a0 = { 558bec5190909090e887fcffff85c07417908d45fc506a006a006890a150126a006a00e8a200000090 }


condition:
	$a0
}