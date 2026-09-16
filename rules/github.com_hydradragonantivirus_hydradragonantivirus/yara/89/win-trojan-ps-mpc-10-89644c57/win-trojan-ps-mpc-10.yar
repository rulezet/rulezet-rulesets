rule Win_Trojan_PS_MPC_10
{
strings:
	$a0 = { 8d963f0359cd21b8024233c999cd21b4408d960001b90c03cd21b801578b8eb4038b96b603cd }


condition:
	$a0
}