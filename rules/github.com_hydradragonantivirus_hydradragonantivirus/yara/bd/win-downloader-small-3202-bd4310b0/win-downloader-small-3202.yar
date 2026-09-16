rule Win_Downloader_Small_3202
{
strings:
	$a0 = { 8d08ea405328d3cadc63e84e6131e64c9d30d37baaf3e34bafd8c17a9d05ff92fc20817c2dc9b2ed76946e28cf4a37f1785b35f04f2c2366b657429b6fe601a87fd5cf0ed748 }


condition:
	$a0
}