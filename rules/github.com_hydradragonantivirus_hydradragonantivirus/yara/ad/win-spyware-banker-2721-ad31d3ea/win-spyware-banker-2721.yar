rule Win_Spyware_Banker_2721
{
strings:
	$a0 = { afe0417a31e2549d872657d63a0ce5b500d26182339682df95eec359efef943de3ea6c9cbcf061d6d379dadcaa7ccc60f93a6a506e9e8983d726b6043668f6de07f362897ef6eda71a588b97fab5 }


condition:
	$a0
}