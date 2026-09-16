rule Win_Trojan_R_24
{
strings:
	$a0 = { fc368b2d81ed030144441e060e1fe88701fcb41a8d96d202cd218cc30e078db65b028dbe5702a5ad01d8051000ab83 }


condition:
	$a0
}