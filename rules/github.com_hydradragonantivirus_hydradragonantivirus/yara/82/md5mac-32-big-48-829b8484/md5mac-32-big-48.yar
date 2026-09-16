rule MD5MAC__32_big_48_
{
strings:
	$a0 = { ac45ef97cd430f29551b7e453411801c96ce77b17c8e722e0aab5a5f18be433621b4219d4db987bcbd279da2c3d75bc7 }

condition:
	$a0
}