rule Win_Trojan_JindraBoot_1
{
strings:
	$a0 = { 138b3e13042e893e47011e07b77cb10fe889004f4f893e1304b106d3e78ec732ffb10ee87600 }


condition:
	$a0
}