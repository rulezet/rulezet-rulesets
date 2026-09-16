rule Win_Spyware_WOW_19
{
strings:
	$a0 = { ff6706ee43acaf7e70b44de26dd282a7c0ad7d23048525bd5e7429ea512c8397ca207e1da8e8455dc8bfaf9b78657a1e8b2e3c9bb151f83e709a11e7a0802cd24aabca4e }


condition:
	$a0
}