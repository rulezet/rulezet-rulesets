rule Win_Trojan_Ebola_3
{
strings:
	$a0 = { 8d92f91ff383f919048f8df9a12da607eda77bf9d569e6a5ed2f7803a3f978fba1f9d55be6d53be5 }


condition:
	$a0
}