rule Win_Trojan_Agent_35433
{
strings:
	$a0 = { 3f70617373776f7264 }

	$a1 = { 6874c82f2f }

	$a2 = { 1f6e7364740b416464 }

	$a3 = { 2647455446494c4553 }

	$a4 = { 37af4c5349442c }

	$a5 = { 7574646f776e505c }


condition:
	$a0 and $a1 and $a2 and $a3 and $a4 and $a5
}