rule Win_Trojan_Fakeav_49
{
strings:
	$a0 = { 6a64687c8af400e83d0000006a76caada8c6ffffff006c008579ffffff00008c71a7a07161cbdc7676bad884d70000ff }


condition:
	$a0
}