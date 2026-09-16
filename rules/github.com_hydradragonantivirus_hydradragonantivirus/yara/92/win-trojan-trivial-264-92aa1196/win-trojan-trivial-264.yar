rule Win_Trojan_Trivial_264
{
strings:
	$a0 = { 0151ba280133c9b44ecd21b8023dba9e00cd21505bb800422bd2cd21b44059ba0001cd21c3 }


condition:
	$a0
}