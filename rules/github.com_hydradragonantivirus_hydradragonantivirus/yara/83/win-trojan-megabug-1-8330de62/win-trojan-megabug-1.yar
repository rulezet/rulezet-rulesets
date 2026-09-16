rule Win_Trojan_MegaBug_1
{
strings:
	$a0 = { 5d81ed0301bf200103fd2e8b862003310583c702ba210303d53bfa72f2 }


condition:
	$a0
}