rule Win_Trojan_BigBug8820_1
{
strings:
	$a0 = { 101715b30c0e8e08da4e7e57060a261015810ecd13a508144c07101b1435a874baf1290e1a2be2 }


condition:
	$a0
}