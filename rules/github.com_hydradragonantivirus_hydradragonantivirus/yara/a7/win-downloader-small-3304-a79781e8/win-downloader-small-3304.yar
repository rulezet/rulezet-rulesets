rule Win_Downloader_Small_3304
{
strings:
	$a0 = { 98963f9b489237fe8b9bd884fa817af1a9840f545e475b6419b5c857415304a314e91fa05eece95834dc5ba062cb00a9e240155538e474e9e3e1 }


condition:
	$a0
}