rule Win_Trojan_Gega228_1
{
strings:
	$a0 = { 870626002ea31d010e1fc70638029090e8c4ff585e1febcf4e6576657220656e64696e672073 }


condition:
	$a0
}