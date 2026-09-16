rule Win_Trojan_VGEN_84
{
strings:
	$a0 = { 8ec08bfeb98200f3a48ed9be8400bf820157ba3b01ad3bc2740aabadab061fb82125cd210e1f0e075ebffc0057 }


condition:
	$a0
}