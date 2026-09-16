rule Win_Trojan_Mybot_7226
{
strings:
	$a0 = { 419cb8219117bf4264114538db27ad27baf3b8ac5f339f23607a9c547bd83da285fd4e8914ff3ca57edc205f74f1d6dc1875fdefbe5c81d041e0ff5898a0ebaab8536db70fc49888c41da0e27c24 }


condition:
	$a0
}