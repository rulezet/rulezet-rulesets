rule Win_Trojan_Theta_1
{
strings:
	$a0 = { ee03b87730cd21fc1ee3281f1e072e80bcf6014d75121e580510002e03840c02502e8b840a0250cbbf00015781c6 }


condition:
	$a0
}