rule Win_Trojan_SubSeven_8
{
strings:
	$a0 = { b59dd5e92afc11292b858487d2d20e6ff3b52f16fc34eedff5104847ad59fc62f21aaa9a94bffc2bfb6afc6b17f16c028f71b32ca6801e57aeabc0808fa2ad76aa9ed64396939cb208a4a8e257fc4cdc }


condition:
	$a0
}