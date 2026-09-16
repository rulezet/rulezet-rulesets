rule Win_Trojan_VGEN_15
{
strings:
	$a0 = { 023dba7b03cd2193b43fb90002ba0b07cd21be0b07817c3c00047402cd208b4402a3df018b4404a3e101b8004233c9 }


condition:
	$a0
}