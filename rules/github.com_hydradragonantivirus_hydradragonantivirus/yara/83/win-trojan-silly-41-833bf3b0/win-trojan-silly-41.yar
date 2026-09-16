rule Win_Trojan_Silly_41
{
strings:
	$a0 = { b1678bd781ea6700e80a004fb440b1038bd7cd21c3cd }


condition:
	$a0
}