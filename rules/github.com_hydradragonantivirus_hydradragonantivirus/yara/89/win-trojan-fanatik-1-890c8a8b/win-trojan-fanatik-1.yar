rule Win_Trojan_Fanatik_1
{
strings:
	$a0 = { 02008d960402cd21b440b902008d960202cd21b80242e82400b440b930018d960601cd213e }


condition:
	$a0
}