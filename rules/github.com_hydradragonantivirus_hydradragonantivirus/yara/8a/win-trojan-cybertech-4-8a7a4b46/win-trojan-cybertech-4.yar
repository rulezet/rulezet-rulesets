rule Win_Trojan_CyberTech_4
{
strings:
	$a0 = { 5d83ed07508db61b0089f7b9e001ac3430aae2fa }


condition:
	$a0
}