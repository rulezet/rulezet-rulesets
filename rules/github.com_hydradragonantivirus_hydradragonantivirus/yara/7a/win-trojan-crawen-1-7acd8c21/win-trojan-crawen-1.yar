rule Win_Trojan_Crawen_1
{
strings:
	$a0 = { bc0002fb83eb198ec353b9c30033ff57be4801fcf3a5cbb409ba3601cd21cd203c383330363e }


condition:
	$a0
}