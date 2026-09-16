rule Win_Trojan_SillyC_139
{
strings:
	$a0 = { ef03b82135cd21be929826813c91e2750b464626813ce0ae7502cd190e075757bf00015e81c6f4008beeb90300f3 }


condition:
	$a0
}