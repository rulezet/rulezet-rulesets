rule Win_Trojan_Bzub_36
{
strings:
	$a0 = { 2f2f3d2a2fbe87f17e1426723d254feb6fbe77b14c7fe70370687000165cded6b9ee0b48544dd7bb68922e18d19a4cef0046747043764341abedd6b8a9875874 }


condition:
	$a0
}