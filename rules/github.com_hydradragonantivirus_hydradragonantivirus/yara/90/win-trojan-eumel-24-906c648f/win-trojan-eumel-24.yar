rule Win_Trojan_Eumel_24
{
strings:
	$a0 = { 5d81ed08018db6270156e80200c3488b9616018bfeb97001ac32c2aae2fac3 }


condition:
	$a0
}