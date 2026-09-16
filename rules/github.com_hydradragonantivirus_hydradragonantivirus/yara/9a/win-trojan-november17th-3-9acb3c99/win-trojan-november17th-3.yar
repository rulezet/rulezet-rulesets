rule Win_Trojan_November17th_3
{
strings:
	$a0 = { 217303e94f01b8023dcd217303e93601 }


condition:
	$a0
}