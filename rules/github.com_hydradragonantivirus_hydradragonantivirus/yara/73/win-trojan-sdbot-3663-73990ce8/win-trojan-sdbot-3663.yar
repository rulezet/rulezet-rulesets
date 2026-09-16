rule Win_Trojan_SdBot_3663
{
strings:
	$a0 = { acbacfc8efef5f89283a99ed5e82865899b96a2f8b70d3b9926168ced48fb1a996ca43bfac51a6dfd459be3beb63643659ae15e00cc78a3be241243e6ee0a69cb2ee8d06bcb2401b94bfc318aa89 }


condition:
	$a0
}