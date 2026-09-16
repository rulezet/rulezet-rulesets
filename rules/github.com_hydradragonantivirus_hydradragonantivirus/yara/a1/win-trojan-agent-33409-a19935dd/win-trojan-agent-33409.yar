rule Win_Trojan_Agent_33409
{
strings:
	$a0 = { 5356bee0db4000bbd8db4000565653e810fdffff83c40c8d4df0e836efffff84c0742f578d7db8c745ec0d000000ff378d4df0e85defffff83c704ff4dec75ee8d4df0e8ddeeffff5653e883fdffff59595f }


condition:
	$a0
}