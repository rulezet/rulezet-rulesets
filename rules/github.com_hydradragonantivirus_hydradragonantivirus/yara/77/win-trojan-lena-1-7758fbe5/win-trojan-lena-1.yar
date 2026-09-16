rule Win_Trojan_Lena_1
{
strings:
	$a0 = { 04d3e02906aa04ba9604b118b440cd215a59b80157cd21b43ecd215a1fb82425cd211f5a }


condition:
	$a0
}