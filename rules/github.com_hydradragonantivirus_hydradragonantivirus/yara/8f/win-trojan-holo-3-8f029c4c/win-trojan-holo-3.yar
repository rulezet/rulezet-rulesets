rule Win_Trojan_Holo_3
{
strings:
	$a0 = { ff298adb293229f9295efd2952575cb12982ecfe }


condition:
	$a0
}