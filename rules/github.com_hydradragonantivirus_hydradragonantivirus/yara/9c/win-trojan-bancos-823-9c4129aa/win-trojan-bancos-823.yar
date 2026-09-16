rule Win_Trojan_Bancos_823
{
strings:
	$a0 = { a6cdf020579a787dce6da713f93e6a1b8bec3e6cbcab5ab1fb328c9134fcc518b99ff2f9db2605166d45471bc0b2b5f3d6ff1da3c4350678e8fc57a11486674703cd8a252288bda5245c22199bbdeaabea8f }


condition:
	$a0
}