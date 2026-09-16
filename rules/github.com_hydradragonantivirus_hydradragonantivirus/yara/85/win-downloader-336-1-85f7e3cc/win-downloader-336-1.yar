rule Win_Downloader_336_1
{
strings:
	$a0 = { 2e677f15d1b3456a0db88440b5bb4bfb72df289459c8c91ad1171baaff289cb22901c1957a5fdce46fdcaf76717a3d63fdb46e179bf053c01c84755407a35b536c422caf7f5db16ff68dd0d92dc3ed3251bd }


condition:
	$a0
}