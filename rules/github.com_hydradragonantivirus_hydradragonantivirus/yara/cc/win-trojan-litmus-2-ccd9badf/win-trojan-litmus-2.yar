rule Win_Trojan_Litmus_2
{
strings:
	$a0 = { 0b1322000f00011617005317b69fb053284c69746d754f32e73300ddb2c2fff5fbeffbfafedbdad60dca3b3f2e6cc6c3 }


condition:
	$a0
}