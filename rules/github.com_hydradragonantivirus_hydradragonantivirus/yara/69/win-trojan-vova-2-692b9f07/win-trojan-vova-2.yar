rule Win_Trojan_Vova_2
{
strings:
	$a0 = { 2f019a00009c005589e531c09a7c022f01b00050bfdc211e57b84f00509a8f0c2f01e860fcbf0d090e579ae00c }


condition:
	$a0
}