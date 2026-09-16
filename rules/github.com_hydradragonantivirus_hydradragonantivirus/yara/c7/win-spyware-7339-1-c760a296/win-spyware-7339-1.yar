rule Win_Spyware_7339_1
{
strings:
	$a0 = { 87ef87db51606183c40487db87ef83ec }


condition:
	$a0
}