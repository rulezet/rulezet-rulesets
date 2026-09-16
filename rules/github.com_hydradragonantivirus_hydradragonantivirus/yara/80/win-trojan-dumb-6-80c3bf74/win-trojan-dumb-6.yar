rule Win_Trojan_Dumb_6
{
strings:
	$a0 = { bf00015781ed06018db60c01a5a48d96e801e8ddffb44e8d96060133c93e888e12023e80be12020377c5cd2172c1b8 }


condition:
	$a0
}