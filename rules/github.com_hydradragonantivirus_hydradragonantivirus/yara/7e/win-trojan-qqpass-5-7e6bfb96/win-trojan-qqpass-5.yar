rule Win_Trojan_QQpass_5
{
strings:
	$a0 = { 94fac2d7153dd96308d837ec82e7b8f03b5b6f205be6b8fc22b10a2bffe86a4e58fe61b57d3b27473af74ed46fd32d322b0b536227cf666121ee79c5becc0172d9ceb0859e2879a9101c670ad10115a6 }


condition:
	$a0
}