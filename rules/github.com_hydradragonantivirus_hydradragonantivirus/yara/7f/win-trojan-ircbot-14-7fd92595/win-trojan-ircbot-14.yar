rule Win_Trojan_IRCBot_14
{
strings:
	$a0 = { 4c6f32476f73508421cbdf97a4decfdc8637e4e3edfd32e57826755acfd8b8966e048bb6e1a69f1357ec275a05fdfa79a3d36c7389508a644c }


condition:
	$a0
}