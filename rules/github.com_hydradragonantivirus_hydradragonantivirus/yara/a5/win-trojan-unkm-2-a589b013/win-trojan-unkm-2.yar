rule Win_Trojan_Unkm_2
{
strings:
	$a0 = { 5db8000081ed06018db64902bf0001a5a48d968000b41acd21b44eb906008d964302cd217215e81c007410b43e }


condition:
	$a0
}