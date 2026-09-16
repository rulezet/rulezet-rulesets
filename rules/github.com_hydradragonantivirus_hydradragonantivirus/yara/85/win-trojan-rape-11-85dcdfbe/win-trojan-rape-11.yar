rule Win_Trojan_Rape_11
{
strings:
	$a0 = { 444f204e4f54fc03f94953545249425554e37c78ff162e434f4dcd696c6520f00faaa2fd203a200f46494c049fe1d2b2554e }


condition:
	$a0
}