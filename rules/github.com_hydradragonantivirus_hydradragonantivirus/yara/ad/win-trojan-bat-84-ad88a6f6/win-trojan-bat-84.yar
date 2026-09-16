rule Win_Trojan_BAT_84
{
strings:
	$a0 = { 64656c20633a5c646f735c756e2a2e2a }

	$a1 = { 6d6b64697220633a5c7370616d68656164 }


condition:
	$a0 and $a1
}