rule Win_Trojan_Prosti_6
{
strings:
	$a0 = { e85c99ffffe8aff8ffffb848704100e82df9ffffb860704100e823f9ffff8d45f8ba78704100e842cffeff }


condition:
	$a0
}