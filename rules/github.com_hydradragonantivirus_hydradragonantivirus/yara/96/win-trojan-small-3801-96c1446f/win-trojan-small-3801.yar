rule Win_Trojan_Small_3801
{
strings:
	$a0 = { 70f3226bb025bcbdd436801a85e197fedd4b99fde33ff50048362392d632ebfbdb6c15ae0746a0a50f28d4a84bf04eee8a66612fd2dd16e51191a0a684e122ec806ca6d856e45edfd9ed0ba9ee21 }


condition:
	$a0
}