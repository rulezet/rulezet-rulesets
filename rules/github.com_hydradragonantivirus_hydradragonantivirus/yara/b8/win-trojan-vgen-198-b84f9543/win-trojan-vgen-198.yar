rule Win_Trojan_VGEN_198
{
strings:
	$a0 = { bd0400cc8dbe3603ffd7aaf6271f335a8cb8115aacbb1154e45e94b51128e50ee50ee954f65f8419106a36f7dff39216 }


condition:
	$a0
}