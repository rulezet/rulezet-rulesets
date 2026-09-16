rule Win_Trojan_Revolt_1
{
strings:
	$a0 = { 060e1fb88235cd2181fb574374408cc381fb485374380706e854007231061eb88225ba48538edaba5743cd218bec8b }


condition:
	$a0
}