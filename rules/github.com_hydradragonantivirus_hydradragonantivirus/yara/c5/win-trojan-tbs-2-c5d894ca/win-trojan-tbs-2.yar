rule Win_Trojan_TBS_2
{
strings:
	$a0 = { 8176a3be2c01cd96b8010089c3b80100cdabbe3c01cd96cd947403e98b00be3801cd96cdb8 }


condition:
	$a0
}