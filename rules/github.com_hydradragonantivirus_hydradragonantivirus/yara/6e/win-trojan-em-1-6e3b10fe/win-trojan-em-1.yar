rule Win_Trojan_Em_1
{
strings:
	$a0 = { 8cd38bd48ed0bcfeff53522d150350bb0001538cda8c }


condition:
	$a0
}