rule Win_Trojan_Munya_3
{
strings:
	$a0 = { 9c505351525657551e060e1f832e130403a11304c1e00633f68ec0b934018a9c557c26881c }


condition:
	$a0
}