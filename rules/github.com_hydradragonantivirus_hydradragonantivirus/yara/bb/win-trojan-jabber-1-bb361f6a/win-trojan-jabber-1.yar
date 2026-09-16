rule Win_Trojan_Jabber_1
{
strings:
	$a0 = { e804b4098bd683c232cd21b41a83ea2ccd21b44eb910008bd6cd2172618a441c241f341f750db44f8bd683c206cd21 }


condition:
	$a0
}