rule Win_Trojan_Sunday_3
{
strings:
	$a0 = { 2180fcff731580fc047210b4ddbf }


condition:
	$a0
}