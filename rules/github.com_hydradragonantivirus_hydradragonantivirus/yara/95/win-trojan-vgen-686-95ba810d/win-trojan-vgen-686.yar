rule Win_Trojan_VGEN_686
{
strings:
	$a0 = { 8cd315337572f9d4ff8ac4fcb41ababe02cd21b44abbfb11cd2172178cc880c4108ec0be00012bffb9e800f3a5b84a }


condition:
	$a0
}