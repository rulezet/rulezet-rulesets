rule Win_Trojan_PS_47
{
strings:
	$a0 = { bb42012e81044e3b46464b75f69ac5b21cdfd7b24f9ae3b87c00067fe6ef0d063918f08d79fc0f7fe635b00979fc91d3360848e0c6 }


condition:
	$a0
}