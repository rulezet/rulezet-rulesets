rule Win_Trojan_Chameleon_7
{
strings:
	$a0 = { f990bb2703b9b8079090fcf8ba191cfcf5f890f93037fb434ae2f4 }


condition:
	$a0
}