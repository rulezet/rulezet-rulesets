rule Win_Adware_Lop_189
{
strings:
	$a0 = { b46aa236df97d5a258df9a05b8bac4ed1aa7910c1b4637e23f4dac5a72ef694bed0aa0c7352d52b861f550c09a31d21d6f633204e50e81a480be4dbf }


condition:
	$a0
}