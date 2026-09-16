rule Win_Trojan_Lost_1
{
strings:
	$a0 = { 9a08130b053f3f3f3f3f3f3f3f434f4d3f03000000ddceddff205ab6671a140b000032383738312e434f4d004d }


condition:
	$a0
}