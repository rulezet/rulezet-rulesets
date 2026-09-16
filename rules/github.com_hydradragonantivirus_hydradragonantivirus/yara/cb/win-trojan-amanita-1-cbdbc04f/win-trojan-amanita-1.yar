rule Win_Trojan_Amanita_1
{
strings:
	$a0 = { b8239ab91402be00002e310486c433c683c602e2f461c3ea0c01cd149c5033c0509d9c5835000075052ef7162b04589de8ccff }


condition:
	$a0
}