rule Win_Trojan_Singapore_1
{
strings:
	$a0 = { 2d03008945048bd7b91a002bf983c70205030103c18905b4408bfa2bd1b90902cd217302eb1c }


condition:
	$a0
}