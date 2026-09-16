rule Win_Trojan_SPS_2
{
strings:
	$a0 = { 4964736637923f525de9e82e94028b55488d9e5679f13e407c18e3478ca3e179cbf9d0c734cfe4edb384abf4b0a1beb44efa95 }


condition:
	$a0
}