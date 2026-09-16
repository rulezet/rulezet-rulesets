rule Win_Adware_Lop_194
{
strings:
	$a0 = { fefc353bbb01e777eab26179086c87131d93d6f3baa33ac3e3beaa72def05b7c371fd1eab260645eb17cae3863f852b51bee3ef86101543ce75bc5fa }


condition:
	$a0
}