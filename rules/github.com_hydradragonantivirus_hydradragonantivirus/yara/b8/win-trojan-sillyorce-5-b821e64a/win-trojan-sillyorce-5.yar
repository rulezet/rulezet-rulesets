rule Win_Trojan_SillyORCE_5
{
strings:
	$a0 = { 213c027304b44ccd21b8ffffcd213d4142750580ff5474edb82135cd21891e6d028c066f0233f68cd8488ed880 }


condition:
	$a0
}