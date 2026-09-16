rule Win_Trojan_PS_23
{
strings:
	$a0 = { 6efa81ed0601b41a8d961f02cd21b4478db64b0299cd21bf0001578db65101b90300f3a48d961602e82200b4 }


condition:
	$a0
}