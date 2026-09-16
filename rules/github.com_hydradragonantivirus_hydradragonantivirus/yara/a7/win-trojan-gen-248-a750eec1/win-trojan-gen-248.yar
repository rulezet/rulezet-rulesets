rule Win_Trojan_Gen_248
{
strings:
	$a0 = { 75636b5589e5b8a0019acd02b10081eca0018cd38ec38cdbfc8d7eb0c57608ac3c4f7202b04faa }


condition:
	$a0
}