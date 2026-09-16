rule Win_Trojan_MemLapse_7
{
strings:
	$a0 = { 81ed03011e06b80342cd213d030074602bc0501fc53684002e89b69e012e8c9ea0018cc0488ed8803e00005a754283 }


condition:
	$a0
}