rule Win_Spyware_WOW_30
{
strings:
	$a0 = { fa9cb8f81a6c75bea9f89553c8815c40742feccf8b7919818d776b3fc015b5dfde95c047a714bc31094fe8a3f9f6863a7b1d7870727fd3669dba323750946f6a83ac86b4 }


condition:
	$a0
}