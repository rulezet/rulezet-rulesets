rule Win_Trojan_Agent_32982
{
strings:
	$a0 = { d899032169219ceb9eb74d22a01afc2c449060c13a73484097d6eb2aafc3d1314c5dfaf1e1d0ca98146ccdb1ac8a9d18a347c6dccbfea4ea51a91ef2f8950810b2d33d07aec3a9f0230bffc8ff67 }


condition:
	$a0
}