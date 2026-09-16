rule Win_Downloader_Agent_35048
{
strings:
	$a0 = { 36673aaa4a2ba4261360e803215196744ee6e62354fbce98b81ab7dc257730e440ce5e59c9eb4080bcc3826545c34fde821b }


condition:
	$a0
}