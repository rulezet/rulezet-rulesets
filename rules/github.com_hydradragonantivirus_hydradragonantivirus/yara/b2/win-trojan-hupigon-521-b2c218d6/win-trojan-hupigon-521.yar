rule Win_Trojan_Hupigon_521
{
strings:
	$a0 = { e5d035446f86c06d9728d9409cfb5b3da97fdf52fa0dd3315015605f409272ebad9239753c6a2a5de3ef06eb21378145b95abb7c5ffdd4f4e7dafbf022a05010eec8c1e922cc87aad0c2f0a6cfdf }


condition:
	$a0
}