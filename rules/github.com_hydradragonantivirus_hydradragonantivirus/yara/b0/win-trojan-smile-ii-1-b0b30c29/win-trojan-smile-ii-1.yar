rule Win_Trojan_Smile_II_1
{
strings:
	$a0 = { b92000ba09049cff1eff03b442b00233c933d29cff1eff03b440b95904ba00009cff1eff03b8 }


condition:
	$a0
}