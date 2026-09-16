rule Win_Trojan_Agent_36369
{
strings:
	$a0 = { 5fca39????12fe9dee01757324a5d43a0d549b4c9212534633275a8fa21f38294e306c71 }


condition:
	$a0
}