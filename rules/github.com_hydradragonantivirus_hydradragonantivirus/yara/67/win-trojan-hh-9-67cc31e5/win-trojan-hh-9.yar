rule Win_Trojan_HH_9
{
strings:
	$a0 = { b440b9a0018d960601cd21e80500b43ecd21c38db62001b9610180340d464975f9c3 }


condition:
	$a0
}