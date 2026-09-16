rule Win_Spyware_Banker_2711
{
strings:
	$a0 = { 6f62efa747c4141fc7176cfa0f3257368a95edfa112a77fb6c51ab243659af60a8d9b789cfe99978aeb35c307f832497bc83ccb493929d700f26 }


condition:
	$a0
}