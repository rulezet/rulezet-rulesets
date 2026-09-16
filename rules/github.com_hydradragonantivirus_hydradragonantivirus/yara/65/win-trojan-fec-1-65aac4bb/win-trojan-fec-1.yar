rule Win_Trojan_Fec_1
{
strings:
	$a0 = { fc33c08ed0bc007cfb8ed88ec0bf????8bf7ad48abc1e0068ec08bf42e803c??750646ac32e403f033ffb99000f2a5bb35000653cb }


condition:
	$a0
}