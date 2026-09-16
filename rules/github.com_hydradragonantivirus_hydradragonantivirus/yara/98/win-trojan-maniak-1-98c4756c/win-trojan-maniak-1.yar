rule Win_Trojan_Maniak_1
{
strings:
	$a0 = { cd1380fa00746480fa01745fbf000233f6b9d200f2a5b90100bb0002b80103cd13b404cd1a }


condition:
	$a0
}