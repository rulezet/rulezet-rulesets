rule Win_Trojan_Fakeav_35
{
strings:
	$a0 = { 5589e581ec3c03000089ada4fdffff8385a4fdffff046800f00000ff15d46046 }


condition:
	$a0
}