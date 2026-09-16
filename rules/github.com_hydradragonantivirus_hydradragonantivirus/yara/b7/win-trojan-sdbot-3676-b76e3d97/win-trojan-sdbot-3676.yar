rule Win_Trojan_SdBot_3676
{
strings:
	$a0 = { fca7a877ff9daebad04b941e2d44ee0cc71519e3f22cc637966ba5bbfea0c707d0dc29933d5bc1d46898054607035a3e998ed1651f81f4c73c95a3eba9368ac4dc13aac4d6e34846e76ab4b5553a }


condition:
	$a0
}