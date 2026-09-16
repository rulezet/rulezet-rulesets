rule Win_Spyware_Banker_1450
{
strings:
	$a0 = { 12c53bfec5c3cf0f3826ceb8d64dcf13c494001a5aacea0d290b051b0c4bad7e0719d44eaad80659cca8d88f805c55b1fcc55595e1ab8e785d10bc565f2cb7fdd424ac5a }


condition:
	$a0
}