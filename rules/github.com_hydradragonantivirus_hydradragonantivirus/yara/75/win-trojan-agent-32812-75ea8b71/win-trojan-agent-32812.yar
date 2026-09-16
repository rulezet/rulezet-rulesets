rule Win_Trojan_Agent_32812
{
strings:
	$a0 = { aee1e67990de3016bdb976cd33b23f3f4cbc28db5786abebaa2b9a315e1e1f2ea0dc75b56d327fa41182e937b2d1730fe6fd832a17670980d27bfa253fea638d49 }


condition:
	$a0
}