rule Win_Trojan_IRCBot_189
{
strings:
	$a0 = { 2864f63e1b1070722f4e2f704a6f09576f6f44b83447cda62ffcff423af22d48c010662d4c696f663f6254e5cf5cff172efdad }


condition:
	$a0
}