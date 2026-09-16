rule Win_Spyware_Banker_3423
{
strings:
	$a0 = { 9c325cd55e3d7f3bcb50bfb18d22bca6cc5e5e491a17e5aa0fa7cd23ac39b8cf652d8aa7fa2899b9f688a6775306a15316a51560440c09df1e1fe0c22d2e18cb6548d8d46bedd190c1c9fe }


condition:
	$a0
}