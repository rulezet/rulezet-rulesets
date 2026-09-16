rule Win_Downloader_15350_1
{
strings:
	$a0 = { 8945f8837df800750733c0e9????????6a0068000100806a006a008b4508508b4df851ff15????????8985f0fdffff83bdf0fdffff0075118b55f852ff15 }


condition:
	$a0
}