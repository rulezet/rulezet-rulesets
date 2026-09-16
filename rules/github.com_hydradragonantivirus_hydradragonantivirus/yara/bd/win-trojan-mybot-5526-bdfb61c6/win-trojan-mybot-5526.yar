rule Win_Trojan_Mybot_5526
{
strings:
	$a0 = { 6444336bf148cad52f426913e7d579159e186bbc8d2a773592ed2c7bca57ed183e1b554d717dd6cd35b5c7f3d842b7ccc74f52af73914e7a9ccf0064840adbdaec234a461b5d }


condition:
	$a0
}