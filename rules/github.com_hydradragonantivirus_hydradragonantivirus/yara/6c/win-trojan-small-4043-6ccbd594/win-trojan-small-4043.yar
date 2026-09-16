rule Win_Trojan_Small_4043
{
strings:
	$a0 = { bdff????fff7d5558dbdef06800081ef320080004ffce81f0000008d90dd1111dd1955008dad910e000081ed8c0e00004d89f829e885c075dcc35589e583ec64 }


condition:
	$a0
}