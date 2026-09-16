rule Win_Trojan_Dialer_3
{
strings:
	$a0 = { d7060c0304fc23f4ec07d3fc9ba6e4dc8b448ee489448fe4e84dd3344de8ececf0f0f4374dd334f4f8f8fcfc8d047d87f0878d9a03f003f809fff040149162d3034c6024c56c36b0b73b909d0bf91133 }


condition:
	$a0
}