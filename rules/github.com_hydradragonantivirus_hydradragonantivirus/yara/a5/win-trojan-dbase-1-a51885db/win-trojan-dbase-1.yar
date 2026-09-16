rule Win_Trojan_DBase_1
{
strings:
	$a0 = { 3d0afb750a86e09dcfe9c106e9780381ff0afb742e3d004b7503e9680480fc6c74ea80fc5b74e580fc3c74e080fc3d }


condition:
	$a0
}