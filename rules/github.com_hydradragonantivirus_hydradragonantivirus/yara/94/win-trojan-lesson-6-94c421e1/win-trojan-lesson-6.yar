rule Win_Trojan_Lesson_6
{
strings:
	$a0 = { bcca004d756381bcdc005944745bb8024233c933d2cd215250b440b966018bd6cd21b8024233c9 }


condition:
	$a0
}