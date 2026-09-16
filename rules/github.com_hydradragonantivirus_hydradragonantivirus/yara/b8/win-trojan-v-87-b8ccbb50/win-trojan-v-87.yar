rule Win_Trojan_V_87
{
strings:
	$a0 = { 8d160000b440cd2172d233c9b440cd2172cab8024233c933d2cd21b90002f7f140a31900b8 }


condition:
	$a0
}