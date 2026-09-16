rule Win_Spyware_Banker_1471
{
strings:
	$a0 = { 3f8ebd19da7d797800b90aac8b63e632b8b0709eaa6bf16f67858420ab09fe26925648eba9bee1bbad52afc8a6400e10a00bb691c406c2aee9d8f1ec7fda6442ad84fca4 }


condition:
	$a0
}