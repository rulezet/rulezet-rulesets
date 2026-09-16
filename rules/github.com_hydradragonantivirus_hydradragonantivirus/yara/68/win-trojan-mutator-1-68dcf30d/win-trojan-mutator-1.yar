rule Win_Trojan_Mutator_1
{
strings:
	$a0 = { 81ed030180be20020174098db61802bf0001a5a5b8ffffcd213d3412745a1e8cd8488ed8803e00005a754da103002d }


condition:
	$a0
}