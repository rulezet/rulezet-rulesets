rule Win_Trojan_KD_2
{
strings:
	$a0 = { ad33864101abbb680f83f9017610babb0bad33864301bb5a08ab49babb04e2e0 }


condition:
	$a0
}