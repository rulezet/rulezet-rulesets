rule Win_Downloader_Banload_586
{
strings:
	$a0 = { 3d0ca2fb0dbbee8c192885929b858f858459e3080880314356b90c88e8c933c4c95ecd31f3a50e4aec991a88ba875ab9265f4dff9db6d6a0bc930ececcf32bf6dbc637f4 }


condition:
	$a0
}