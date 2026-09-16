rule Win_Trojan_Asmodeous_3
{
strings:
	$a0 = { 3047014be9d3ffc4bdd19c3c83daa051effa428383cee16dfbacbd61fb8f68760b8f2fc9ea8290edb8a8b4ecc1610b }


condition:
	$a0
}