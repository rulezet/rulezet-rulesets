rule Win_Spyware_ye_86
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]53995daa6e15406a14b9e4d6fe9bcb }


condition:
	$a0
}