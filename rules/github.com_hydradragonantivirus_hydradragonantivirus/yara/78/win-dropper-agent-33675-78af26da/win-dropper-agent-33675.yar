rule Win_Dropper_Agent_33675
{
strings:
	$a0 = { d98bfa8bf0535753566a016800040000e873dfffff83e8025f5e5bc3535657558bea8bf88bc7e801beffff8bf0bb01000000eb01433bf37c07807c1fff2076f43bf37d0a8bc5e821bbffffeb174e807c }


condition:
	$a0
}