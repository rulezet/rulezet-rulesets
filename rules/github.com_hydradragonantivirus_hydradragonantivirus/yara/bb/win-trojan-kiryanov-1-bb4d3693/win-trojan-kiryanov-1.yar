rule Win_Trojan_Kiryanov_1
{
strings:
	$a0 = { 1304b106d3e08ec033ffb9b20190be3e7cf3a4506a539090cb54484e583a4772616e64732c5061 }


condition:
	$a0
}