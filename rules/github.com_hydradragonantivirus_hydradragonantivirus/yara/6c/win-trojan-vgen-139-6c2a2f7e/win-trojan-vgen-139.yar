rule Win_Trojan_VGEN_139
{
strings:
	$a0 = { 90e8c80650b4d93037638f95c7f8163ef7414f2bbbf67cbbecb50935376f425f8c34361c2936371c292737bb312737 }


condition:
	$a0
}