rule Win_Trojan_Helicopter_1
{
strings:
	$a0 = { 83ea03895401c6440351b440b90400ba0903cd215a33c9b80042cd21b440b9090333d2cd211f }


condition:
	$a0
}