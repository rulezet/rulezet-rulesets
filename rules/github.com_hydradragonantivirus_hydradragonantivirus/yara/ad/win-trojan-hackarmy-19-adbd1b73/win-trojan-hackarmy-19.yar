rule Win_Trojan_Hackarmy_19
{
strings:
	$a0 = { 75495281331ddf14a7388ee02c9f72b507b84af1e61fe5bd09152c13e51769b68947b976b0a426064db2b20a3c11e8ae49eb765de8122aec4dd94df25b65d5c7 }


condition:
	$a0
}