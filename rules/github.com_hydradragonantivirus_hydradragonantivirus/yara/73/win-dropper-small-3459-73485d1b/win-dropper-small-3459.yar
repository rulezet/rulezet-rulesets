rule Win_Dropper_Small_3459
{
strings:
	$a0 = { 8bd0b8e067001059e844e0ffffe8e7daffff6a008b15546700108b0d58670010b8e0670010e827e0ffffe8cadaffffb8e0670010e838e0ffffe8bbdaffff6a01a1d0670010e883ecffff50e8b9f1ffff }


condition:
	$a0
}