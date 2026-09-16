rule Win_Trojan__0406_0010_000_1
{
strings:
	$a0 = { 0881fb53427502f9c3f8c39c2eff1e9006c3b003cf1e0633c08ed88cc88ec0be9000bffb05 }


condition:
	$a0
}