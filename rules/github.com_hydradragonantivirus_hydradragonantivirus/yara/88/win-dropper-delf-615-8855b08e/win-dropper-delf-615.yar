rule Win_Dropper_Delf_615
{
strings:
	$a0 = { 6a008d442404506a1e68544040006af5e8a6e0ffff50e8c0e0ffff6a008d442404506a0268a42f40006af5e88be0ffff50e8a5e0ffff5a }


condition:
	$a0
}