rule Win_Trojan_VGEN_773
{
strings:
	$a0 = { 8ed8b409ba0000cd21be0201b90100b401cd213c0d740d3c08740688044146ebee4eebebb409baa601cd21be02 }


condition:
	$a0
}