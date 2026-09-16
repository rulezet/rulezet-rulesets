rule Win_Dropper_Agent_34333
{
strings:
	$a0 = { 558bec83ec5c837d0c0f742b837d0c468b4514750d834818108b0d6443420089 }

	$a1 = { 898786db555353ff4e4c4dff716e6fffc1bfbdffcac8c7ffecebebfff6f5f3ffc6c4c3ff898786ffa39f9fffbfbdbbffaba7a5ffdad9d8fff4f3f2ffa4a1a1ff565657ff4d4c4dff838182f6f5f4f4ffffffffffffffffffffffffff9c9a9aff }


condition:
	$a0 and $a1
}