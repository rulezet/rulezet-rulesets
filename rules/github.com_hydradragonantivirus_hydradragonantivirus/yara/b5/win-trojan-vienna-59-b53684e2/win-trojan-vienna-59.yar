rule Win_Trojan_Vienna_59
{
strings:
	$a0 = { b440b9900289f281eaf801cd21721e }


condition:
	$a0
}