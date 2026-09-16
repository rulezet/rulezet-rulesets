rule Win_Trojan_EvilHomer_2
{
strings:
	$a0 = { 40b9ce008d960601cd21b800429933c9cd21b440b906008d96c801cd21b43ecd21b44fcd217391 }


condition:
	$a0
}