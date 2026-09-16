rule Win_Trojan_Mybot_4956
{
strings:
	$a0 = { 7bc0bb6cf7cb1cb9242ce1d5aefc895ac9d5d191e906e55e76489c2422b1477853165285f0cf0b1bfd0b9bf915831f6e4ee082d3ee78a4d8f34b8efef77f19753655010b8f58bf2ee36e8d424f4e }


condition:
	$a0
}