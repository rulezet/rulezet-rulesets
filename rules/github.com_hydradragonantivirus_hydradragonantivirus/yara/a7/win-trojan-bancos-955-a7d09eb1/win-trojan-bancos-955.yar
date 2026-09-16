rule Win_Trojan_Bancos_955
{
strings:
	$a0 = { 764690d5d7027d5bf099b7ed9984ab5b1a692fd3f7b8f7601a6a96f4c7ed789e01bb7f58eaf9beb6c2739481206d2c8641dd25f2d3fa18ca3b2ddc4ab52fef9b12fccd5b5c808f97c2fb729f8ab2 }


condition:
	$a0
}