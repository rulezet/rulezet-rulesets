rule Win_Trojan_Trackswap_1
{
strings:
	$a0 = { 8edfbe007c8bdefa8ed78be6fba1130448a31304b106d3e08ec006bd270055b90001f3a5cbbe4c00bf8f00a5a5fac744fc16018c44febe2400bff401a5a5 }


condition:
	$a0
}