rule Win_Trojan_Fakecodecs_7
{
strings:
	$a0 = { eb5069fdb400af5d134cf7a169aa23299d0006cff33238d0b70021dd77e255cc }


condition:
	$a0
}