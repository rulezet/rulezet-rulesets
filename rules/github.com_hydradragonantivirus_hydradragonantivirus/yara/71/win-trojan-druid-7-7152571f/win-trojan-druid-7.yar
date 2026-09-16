rule Win_Trojan_Druid_7
{
strings:
	$a0 = { 02ebfcbaed01b80125cd21b003cd21baed01b80125cd21b001cd21b44732d2bef801cd21baee01b44ecd217303eb }


condition:
	$a0
}