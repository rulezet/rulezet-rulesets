rule Win_Trojan_Startpage_416
{
strings:
	$a0 = { 568bf1e811fbffff84c07429ff74240c8bceff742418ff742418e810ffffff6840124000ffb6080100008bceff742410e805fdffff }


condition:
	$a0
}