rule Win_Trojan_Sirius_15
{
strings:
	$a0 = { 01be1e3fbfdf01f78431374643434f09ff75f690f63f1f6298c1dff203beddab3d4b620ce6b1fffa36bb2911a3a1a93f02b3b3bb2eb3e474bee4b011 }


condition:
	$a0
}