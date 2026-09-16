rule Win_Trojan_Jinx_2
{
strings:
	$a0 = { be0001561e068bec565fb800908ec0bb030126813f4a697505c6060e0101b9dc0281e90001890e0901fcf3a406b884 }


condition:
	$a0
}