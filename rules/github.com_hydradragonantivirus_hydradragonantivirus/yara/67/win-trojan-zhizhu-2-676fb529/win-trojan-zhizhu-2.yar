rule Win_Trojan_ZhiZhu_2
{
strings:
	$a0 = { 66ffc0660fade010e8d3e8894d??f9d2ed54f98b4d??f8ff75??8f042466157ec3660fa3d68bc7e88cecffff }


condition:
	$a0
}