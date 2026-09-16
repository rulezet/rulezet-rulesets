rule Win_Downloader_394_1
{
strings:
	$a0 = { 395dbc8d45d0508d854cffffff74068d853cffffff508d854cfbffff685840400050ff153030400083c41068544040008d85dcfdffff50ffd78d85dcfeffff508d85dcfdffff50ffd68d854cfbffff508d }


condition:
	$a0
}