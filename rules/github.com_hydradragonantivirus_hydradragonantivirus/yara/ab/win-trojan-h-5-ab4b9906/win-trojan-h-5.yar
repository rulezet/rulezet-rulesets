rule Win_Trojan_H_5
{
strings:
	$a0 = { b440b93601cd63b8004233c98bd1cd63 }


condition:
	$a0
}