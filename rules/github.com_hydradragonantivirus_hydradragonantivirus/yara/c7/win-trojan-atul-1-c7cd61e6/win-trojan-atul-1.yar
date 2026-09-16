rule Win_Trojan_Atul_1
{
strings:
	$a0 = { 8b0181fa751a813e8d0127127512b080bba105b96000000743e2fbc310007201c8e1f0f0f9a0c2e9f2f4e8e4e1f9aca0d6c1c9d3c8c1ccc983a0d7e9f4e8a0eceff6e5a0e6f2efed }


condition:
	$a0
}