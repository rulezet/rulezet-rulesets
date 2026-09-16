rule Win_Trojan_Druid_3
{
strings:
	$a0 = { 02ebfcbae001b80125cd21b003cd21bae001b80125cd21b001cd21b44732d2bee901cd21bae101b44ecd217303eb }


condition:
	$a0
}