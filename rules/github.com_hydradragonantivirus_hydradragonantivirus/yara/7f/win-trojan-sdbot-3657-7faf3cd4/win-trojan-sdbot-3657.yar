rule Win_Trojan_SdBot_3657
{
strings:
	$a0 = { 18094c0f5e7c00dc805bb9ef85a5697a00d3320eea71dc7b7ceafddfffaaf80ce8b3f47ca3a4ee9a360a5a3626bdfdea7f7fd76fe8ca24545e4fa699e835c00efa417d4d5cb9c69773e225a23cde }


condition:
	$a0
}