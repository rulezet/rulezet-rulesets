rule Win_Trojan_DigitalParas_1
{
strings:
	$a0 = { 0300bab503cd2189d681c298563914746eb8024233 }


condition:
	$a0
}