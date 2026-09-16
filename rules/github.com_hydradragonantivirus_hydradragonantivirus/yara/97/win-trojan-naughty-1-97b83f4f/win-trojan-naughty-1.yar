rule Win_Trojan_Naughty_1
{
strings:
	$a0 = { fcac32d8e2fb2e[1-8]b801facd210ac02bff2ec536????b9??0851561ef3a48cc3075f592ac0f3aa0eb8????5053b8????50cb }


condition:
	$a0
}