rule Win_Trojan_Revenge_2
{
strings:
	$a0 = { 010e1fe9ac04505352561e0626803f007416b425268a07268b1483c602268e1ccd214383c602ebe4b449cd21 }


condition:
	$a0
}