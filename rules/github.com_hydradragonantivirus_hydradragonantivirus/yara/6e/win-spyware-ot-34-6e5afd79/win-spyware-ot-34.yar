rule Win_Spyware_ot_34
{
strings:
	$a0 = { 76928f882b95ed629f1aa7a9fab7be314f7fdb6800da12e27136b3e5b727313560e273f818f06163c8a8005f2e662b566c93ba511d90ee8c6317fede }


condition:
	$a0
}