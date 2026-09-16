rule Win_Trojan_Oeba_1
{
strings:
	$a0 = { 434f4d034558455589e5b82c049a7c027b0081ec2c04c4 }


condition:
	$a0
}