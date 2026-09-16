rule Win_Trojan_Delf_991
{
strings:
	$a0 = { b66d0368196c4c76130584b8b7b3c3fe87859a05f1ff2f915dc698f028830ade57066d4dddc7bfffffff375eab074b0cd511edd7e038b8c9a32b094704b99bca64bc18c6efe8265310ffff }


condition:
	$a0
}