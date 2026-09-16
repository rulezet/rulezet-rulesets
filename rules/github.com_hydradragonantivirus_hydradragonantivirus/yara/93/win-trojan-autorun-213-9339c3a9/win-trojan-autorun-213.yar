rule Win_Trojan_Autorun_213
{
strings:
	$a0 = { 5b6175746f72756e5d203b64386f206f70656e3d6366763930682e636f6d }


condition:
	$a0
}