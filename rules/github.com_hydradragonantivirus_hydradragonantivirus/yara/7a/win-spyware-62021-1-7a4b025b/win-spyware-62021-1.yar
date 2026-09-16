rule Win_Spyware_62021_1
{
strings:
	$a0 = { 4c6569746f7220536d61727443617264 }

	$a1 = { 2a2e637274 }

	$a2 = { 5c646174652e6c6f67 }

	$a3 = { 5c70617970616c322e747874 }


condition:
	$a0 and $a1 and $a2 and $a3
}