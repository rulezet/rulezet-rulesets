rule Win_Trojan_Stoned_3
{
strings:
	$a0 = { 03cd13b864002ea30501be0000bf9f01b99f01fcf3a4bf170081c79f01b0808805bb9f01b9 }


condition:
	$a0
}