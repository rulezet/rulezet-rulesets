rule Win_Trojan_Druid_1
{
strings:
	$a0 = { bafe02b80125cd21b003cd21bafe02b80125cd21b001cd21b44732d2be????cd21baff02b44ecd217303 }


condition:
	$a0
}