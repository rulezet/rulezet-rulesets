rule Win_Trojan_Yosha_2
{
strings:
	$a0 = { 7c8be3be1304ff0cfcadc1e0068ec0be037cb9b80133 }


condition:
	$a0
}