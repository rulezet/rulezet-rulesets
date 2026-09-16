rule Win_Trojan_Mephisto_1
{
strings:
	$a0 = { 01b440b9e8038b5443cd21b80042b90000ba0000cd21b80040b90300836c41038d5440cd21 }


condition:
	$a0
}