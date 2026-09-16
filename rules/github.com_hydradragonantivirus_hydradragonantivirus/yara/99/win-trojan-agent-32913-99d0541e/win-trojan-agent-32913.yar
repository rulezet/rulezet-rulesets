rule Win_Trojan_Agent_32913
{
strings:
	$a0 = { dea27d19bff8f924c5c6099a699d57cfebe6e0dc90d58237fde0bd2822402f38325d8d2088b6fcce577852cd6f20e543cd1abc1a9e67e8c067e9656b347a7f48c7c1b7ccab7e4cf0ada852452c1f }


condition:
	$a0
}