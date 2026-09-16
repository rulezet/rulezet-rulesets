rule Win_Trojan_Gen_8
{
strings:
	$a0 = { f08bfebed203b98600f3a42bd2b9010032c0bbd80fcd269d7303e962fee961fee800005b83 }


condition:
	$a0
}