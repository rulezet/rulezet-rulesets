rule Win_Trojan_Div_1
{
strings:
	$a0 = { 06840026a35e02268c1e60021ffac706840051028c068600fb071fb8ba0250c39c3dbaba740b80 }


condition:
	$a0
}