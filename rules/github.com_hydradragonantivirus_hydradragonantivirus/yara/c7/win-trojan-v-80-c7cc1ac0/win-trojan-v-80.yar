rule Win_Trojan_V_80
{
strings:
	$a0 = { b8044bcd2181ff55aa74611e2bc08ed8bf84008e45028b1d2e8c8689012e899e87011f1e078cc08bd84b8edb2b }


condition:
	$a0
}