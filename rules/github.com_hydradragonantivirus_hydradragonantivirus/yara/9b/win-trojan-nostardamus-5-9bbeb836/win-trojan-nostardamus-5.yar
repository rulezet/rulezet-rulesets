rule Win_Trojan_Nostardamus_5
{
strings:
	$a0 = { 1908ba1b34cfca15cdef3afdbf18da4b5919c151e28919518c8a0ca2691bcdf03afda91863dc19e2 }


condition:
	$a0
}