rule Win_Dropper_Karn_1
{
strings:
	$a0 = { 4d58c4ad80f1a3b241ef814684db75530dc423fb607b9660bfab8c9c443023908b4ad85580eac9353d6f8aef4a78fdd4ee56cf3d7c757d178cc0df6136 }


condition:
	$a0
}