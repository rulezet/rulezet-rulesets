rule Win_Trojan_FakeLogin_1
{
strings:
	$a0 = { 733d50616c74616c6b000000558bec51538bda8945fc8b45fce86a9afaff33c05568dbac450064ff30648920eb1c8b55fcb8f0ac4500e8a19bfaff8bc88d45fc }


condition:
	$a0
}