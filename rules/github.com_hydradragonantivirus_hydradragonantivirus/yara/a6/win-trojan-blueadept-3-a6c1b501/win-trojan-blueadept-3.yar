rule Win_Trojan_BlueAdept_3
{
strings:
	$a0 = { 5e9b8da3200c84a07bd0d6708dab520514b14d4481b8e87a8e002fa466ada026d637da5833c2525f2cf23b5fe3e1c6f3f8807f9b0aa0d4d8237e8da987476175 }


condition:
	$a0
}