rule Win_Trojan_Unhandled_1
{
strings:
	$a0 = { 01b440cd21c604e958054801894401c74403931133d233c9b80042cd218bd659b440cd21b43e }


condition:
	$a0
}