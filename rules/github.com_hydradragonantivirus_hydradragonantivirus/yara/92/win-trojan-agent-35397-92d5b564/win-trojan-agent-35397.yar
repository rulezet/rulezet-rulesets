rule Win_Trojan_Agent_35397
{
strings:
	$a0 = { 685606621be80d3500009c83fb01608d6424300f84c94dffff84cf546083fb02ff742404ff7424 }


condition:
	$a0
}