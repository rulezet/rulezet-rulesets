rule Win_Trojan_LLP_1
{
strings:
	$a0 = { 0901b430330602012e80360d01062e89054b83fb0075de }


condition:
	$a0
}