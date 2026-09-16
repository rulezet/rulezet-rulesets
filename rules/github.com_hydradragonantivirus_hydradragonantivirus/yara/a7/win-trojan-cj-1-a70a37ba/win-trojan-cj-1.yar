rule Win_Trojan_Cj_1
{
strings:
	$a0 = { bf00015703f7b9030051fcf3a45f50b82135cd2180fb5c74358cd8488ed8803e00005a7527899c31018c8433 }


condition:
	$a0
}