rule Win_Trojan_Savno_1
{
strings:
	$a0 = { 88a0400050c645fb65e88614000083c4108d85b8feffff508d85b8fcffff50ff151c9040008bf083feff7454f685b8feffff10753283bdd4feffff00752981bd }


condition:
	$a0
}