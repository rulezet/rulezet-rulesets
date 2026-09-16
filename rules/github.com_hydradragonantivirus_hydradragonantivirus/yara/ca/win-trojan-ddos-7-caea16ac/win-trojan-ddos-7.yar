rule Win_Trojan_DDoS_7
{
strings:
	$a0 = { 1c1b1b0f505b4800000000 }

	$a1 = { 544f524d3a25737c25737c8ed8d78ed8d78ed8abababab8ede8be6e9ababab8ede8bece9abababecc7c4c9cac7e6cec6c4d9d2f8dfcadfded8eed3 }


condition:
	$a0 and $a1
}