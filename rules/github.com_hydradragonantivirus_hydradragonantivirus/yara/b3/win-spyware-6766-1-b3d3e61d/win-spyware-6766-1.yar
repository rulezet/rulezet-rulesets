rule Win_Spyware_6766_1
{
strings:
	$a0 = { 60e806000000eb022408eb0c[0-50]e800000000[0-6]8b??245881????????01 }


condition:
	$a0
}