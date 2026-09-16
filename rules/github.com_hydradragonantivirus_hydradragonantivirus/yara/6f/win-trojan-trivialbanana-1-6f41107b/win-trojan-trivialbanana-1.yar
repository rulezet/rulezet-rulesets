rule Win_Trojan_TrivialBanana_1
{
strings:
	$a0 = { ba8501b44ecd217245b80043ba9e00cd2151b8014333c9cd21b8023dba9e00cd21722793b80057cd215152ba0001b440 }


condition:
	$a0
}