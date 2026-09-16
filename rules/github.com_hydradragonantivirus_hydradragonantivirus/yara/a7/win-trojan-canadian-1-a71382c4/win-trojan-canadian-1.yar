rule Win_Trojan_Canadian_1
{
strings:
	$a0 = { cd213c02740d77168d16e806b409cd21e9f6008d161b07b409cd21eb4090a12c008ec033ffb9ff7f32c0f2ae2680 }


condition:
	$a0
}