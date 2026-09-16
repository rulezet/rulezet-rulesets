rule Win_Trojan_SillyC_19
{
strings:
	$a0 = { 018b36010103f757a4a5b44eba650003d6cd21724deb06b44fcd21ebf6b8023dba9e00cd2172f05293b43fb1032b }


condition:
	$a0
}