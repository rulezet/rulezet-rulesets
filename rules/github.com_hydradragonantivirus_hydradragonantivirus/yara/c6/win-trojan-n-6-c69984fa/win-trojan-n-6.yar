rule Win_Trojan_N_6
{
strings:
	$a0 = { 8035d647e2f93ed6d63ed6d68b573bd0d63dd6ed3e50dbd61bf6d3bdd7e81150dbd6ed3e1a3df986858387848180 }


condition:
	$a0
}