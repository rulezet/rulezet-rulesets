rule Win_Trojan_Agent_36216
{
strings:
	$a0 = { 737461727420433a5c72646b7373657475702e6578650d0a65786974 }


condition:
	$a0
}