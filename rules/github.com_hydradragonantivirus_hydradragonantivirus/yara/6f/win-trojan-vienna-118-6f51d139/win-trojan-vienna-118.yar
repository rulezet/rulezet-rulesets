rule Win_Trojan_Vienna_118
{
strings:
	$a0 = { c30790c607205b2bf983c70205030103c18905b4408bfa2bd1b95802cd787303eb1f903d5802 }


condition:
	$a0
}