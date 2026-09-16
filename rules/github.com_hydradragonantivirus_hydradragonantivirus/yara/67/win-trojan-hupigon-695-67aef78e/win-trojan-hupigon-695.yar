rule Win_Trojan_Hupigon_695
{
strings:
	$a0 = { c2c508ae22d8730e86a5623cd46256873bd4f59d338099a2da97c4c902cd3e92bd13bffeb41edd0014016a971705a1fbe4ab623adf9ec07fbfab6278 }


condition:
	$a0
}