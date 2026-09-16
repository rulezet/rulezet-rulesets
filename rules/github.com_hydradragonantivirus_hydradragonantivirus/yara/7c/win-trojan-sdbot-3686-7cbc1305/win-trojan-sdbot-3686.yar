rule Win_Trojan_SdBot_3686
{
strings:
	$a0 = { e70fe0de3a73c5880544a2e5729a0d6ae7de0062f251d66e01c8a72503889f8991cabfbe0e626d1e535fff64f5fcf2d5f6a5b91216abab79ebdc8bfa65ae7d2cea5321511b07478dddc4be6746b0 }


condition:
	$a0
}