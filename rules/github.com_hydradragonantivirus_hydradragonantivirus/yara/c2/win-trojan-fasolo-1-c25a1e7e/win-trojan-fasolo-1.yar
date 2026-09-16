rule Win_Trojan_Fasolo_1
{
strings:
	$a0 = { 2180fe0c753080fa04752bb402b207cd21e4210c02e621b403b080b500b101b600b280bb0000cd13b402b207cd }


condition:
	$a0
}