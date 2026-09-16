rule Win_Trojan_FCruncher_1
{
strings:
	$a0 = { 35cd21891e6f018c067101ba0301b82125cd21803e8401ff754d2e8e062c0033ff8bc7af9c4f9d75fa47478cc08e }


condition:
	$a0
}