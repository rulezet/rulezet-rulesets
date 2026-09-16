rule Win_Trojan_SillyOR_8
{
strings:
	$a0 = { cd213c05751eb860008ec00e1f33ffb14df3a48ed8ba2700b82125cd21ba4800b0ffcd21c380fc3e751c1e525150 }


condition:
	$a0
}