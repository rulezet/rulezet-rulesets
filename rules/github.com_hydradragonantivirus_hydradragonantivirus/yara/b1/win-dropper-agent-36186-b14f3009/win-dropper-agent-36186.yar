rule Win_Dropper_Agent_36186
{
strings:
	$a0 = { 7478742e3233656c6966676f6c5c73776f646e69575c3a43 }

	$a1 = { 5c6e75525c6e6f }

	$a2 = { 6578652e6d74736b6e735a }


condition:
	$a0 and $a1 and $a2
}