rule Win_Trojan_Agent_33054
{
strings:
	$a0 = { ee0fbe0c0240d1dfa0e14d8a89963ceaff75efc6043e968097ab7e5030fd16e446b00452ef0c23d201a53ad90ba97334021cdac70a3df45540200734b2ba155c21c2496facafc1fd4dd58740e60b }


condition:
	$a0
}