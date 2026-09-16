rule Win_Trojan_Mypoo_2
{
strings:
	$a0 = { 476dcb08da220d270d3a70c99fec21534a4f494e20234dc9d36b01ff0f573e2107596266e09f9d38b223e0b8641913b8bbb904dddccfddc3e8e5920916b49dcaf103d40b96d0 }


condition:
	$a0
}