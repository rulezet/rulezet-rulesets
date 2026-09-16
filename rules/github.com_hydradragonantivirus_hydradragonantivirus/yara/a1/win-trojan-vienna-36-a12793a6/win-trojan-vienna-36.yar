rule Win_Trojan_Vienna_36
{
strings:
	$a0 = { 2fcd21891c8c440207ba5f0003d6b41acd21065683c61a8bd68e062c00bf00008bf2acb90080 }


condition:
	$a0
}