rule Win_Trojan_Acid_1
{
strings:
	$a0 = { 212d0300c606ae02e9a3af02b440b9a20299cd21b800422bc9cd21b440b91a00baae02cd21b8 }


condition:
	$a0
}