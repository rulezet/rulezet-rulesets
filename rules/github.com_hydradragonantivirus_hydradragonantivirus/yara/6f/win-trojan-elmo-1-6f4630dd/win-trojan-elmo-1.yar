rule Win_Trojan_Elmo_1
{
strings:
	$a0 = { fe864c02e81000b4408d960401b94901cd21e80200eb88e800005f81ef3802b900018a954c02 }


condition:
	$a0
}