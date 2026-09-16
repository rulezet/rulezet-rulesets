rule Win_Trojan_Sirius_25
{
strings:
	$a0 = { 5d81ed0a018db62801568b960a01b90f018bfeac32c2aad1cae2f8c3 }


condition:
	$a0
}