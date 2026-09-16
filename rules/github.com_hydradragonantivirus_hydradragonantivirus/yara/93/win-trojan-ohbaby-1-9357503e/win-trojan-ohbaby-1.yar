rule Win_Trojan_Ohbaby_1
{
strings:
	$a0 = { 6162790a0d008db61f00b82501ffd08db62800b82501ffd08db63800b82501ffd08db64800 }


condition:
	$a0
}