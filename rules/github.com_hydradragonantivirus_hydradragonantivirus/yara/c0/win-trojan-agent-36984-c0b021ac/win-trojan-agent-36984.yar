rule Win_Trojan_Agent_36984
{
strings:
	$a0 = { 8b8514ffffff03054ca44300898514ffffff8b8520ffffff48898520ffffff8b8514ffffff40898514ffffff8b450805c2e10000898514ffffffff9514ffffff }


condition:
	$a0
}