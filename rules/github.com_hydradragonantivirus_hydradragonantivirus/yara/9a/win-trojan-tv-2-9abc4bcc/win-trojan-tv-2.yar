rule Win_Trojan_TV_2
{
strings:
	$a0 = { 01b86e4bcd213d5456750ac705eb59c6450290ffe78c }


condition:
	$a0
}