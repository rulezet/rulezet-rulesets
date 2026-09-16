rule Win_Trojan_V_117
{
strings:
	$a0 = { b82135cd21891e????8c06????b82125ba????cd215bb81c355359cd21891ef3018c }


condition:
	$a0
}