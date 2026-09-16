rule Win_Trojan_SMS_2
{
strings:
	$a0 = { b82135cd21891e????8c06????b82125ba????cd21071fbf00febec501b90d }


condition:
	$a0
}