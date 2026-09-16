rule Win_Trojan_MadSatan_1
{
strings:
	$a0 = { 1ef2052e8c1ef6052e8a1ef505b86335cd212e813f65137503e93301b82135cd212e8c06e4052e891ee2058e1e2c }


condition:
	$a0
}