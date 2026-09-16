rule Win_Trojan_Nomad_1
{
strings:
	$a0 = { 03003e8986f303b8004233c999cd21b03e040286e08d96f203b90400cd21b8024233c999cd21b0 }


condition:
	$a0
}