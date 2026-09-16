rule Win_Trojan_Emperor_5
{
strings:
	$a0 = { 010000000000a6040000090000009e08000055 }


condition:
	$a0
}