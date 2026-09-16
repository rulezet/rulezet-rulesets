rule Win_Trojan_Serbu_1
{
strings:
	$a0 = { 25ba8e0ccd8ec3e961f3050200c306e8c2ffb440b9fa0c99cd8e720239c89ce8b2ff9d07c3fa }


condition:
	$a0
}