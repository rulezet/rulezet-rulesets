rule Win_Spyware_Banker_5881
{
strings:
	$a0 = { 87856c6696a2a385584ffcf19fd5c90ae85fdf1b40a17dc4386a437316f47d67b69be9e7f62d720d5faf2858056c23430a1a39be262e0caed2ed7f5e44cbc98d22c894b0 }


condition:
	$a0
}