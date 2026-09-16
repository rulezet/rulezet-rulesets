rule Win_Trojan_Serbu_4
{
strings:
	$a0 = { 8e0ccd8ec3e961f3050100c306e8c2ffb440b9fa0c99cd8e720239c89ce8b2ff9d07c3fa }


condition:
	$a0
}