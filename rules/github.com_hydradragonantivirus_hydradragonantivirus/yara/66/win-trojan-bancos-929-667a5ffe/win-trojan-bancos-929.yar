rule Win_Trojan_Bancos_929
{
strings:
	$a0 = { bffdfa02c1acf4e1629e90dbbb1aa0ad73260bb2fadc8dc944551cc964c7c4287768191538f562e9e452f39d7513ed0a3928963f749bbd2686e254e3717d7ace85b0a845acd9e847b4ba2a30ecee }


condition:
	$a0
}