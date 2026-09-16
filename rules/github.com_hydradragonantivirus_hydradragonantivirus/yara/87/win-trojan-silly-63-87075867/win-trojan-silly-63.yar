rule Win_Trojan_Silly_63
{
strings:
	$a0 = { 5b4175746f52756e5d0d0a6f70656e3d4d725f436f6f6c466163652e736372 }


condition:
	$a0
}