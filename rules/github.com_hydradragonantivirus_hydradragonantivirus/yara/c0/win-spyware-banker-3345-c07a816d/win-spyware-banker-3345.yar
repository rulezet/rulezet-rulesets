rule Win_Spyware_Banker_3345
{
strings:
	$a0 = { db7790e48ffdfffdb7e5053d0683a49381bd61abf9819cfceb01fa1888babe7dcd89b27e2cbd0ba1e1ff4a64ac9fa4ff554e18ce1ab93528b772cbff86fb38e1fe22ce98b43e }


condition:
	$a0
}