rule Win_Spyware_4095_1
{
strings:
	$a0 = { 52538bda5b893c24565e515183c404565683c404893c245181d1fa296f222b }


condition:
	$a0
}