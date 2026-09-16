rule Win_Trojan_Bzub_51
{
strings:
	$a0 = { f558b6706372af2d20abbfd4135c5bec5055505d203d43dbacbaae3a0326133dd72e70de6baa75932db3686513075a6b9bf96336b7788e53876c7bd5be7f69d409a4701f5cac }


condition:
	$a0
}