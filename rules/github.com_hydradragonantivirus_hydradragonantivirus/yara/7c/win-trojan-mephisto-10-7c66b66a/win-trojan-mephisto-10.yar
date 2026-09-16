rule Win_Trojan_Mephisto_10
{
strings:
	$a0 = { fc368b2d81ed030144441e060e1fe88a01fcb41a8d96d602cd218cc30e078db65e028dbe5a02a5ad03c3051000ab83 }


condition:
	$a0
}