rule Win_Trojan_Ontario_7
{
strings:
	$a0 = { 6e4bcd213d5456750ac70589d8c64502c3ffe78cc80510 }


condition:
	$a0
}