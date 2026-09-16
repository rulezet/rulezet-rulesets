rule Win_Trojan_Bancos_724
{
strings:
	$a0 = { dc8cf247938ce81c0d21dfcca1a9b41c1bb4139d52f62f5f6e235e53c2773fef7d0f2566e0325e0e94efd8af5d6e7d1f1ca748b779a57164b7b37d02e52a7d65250fb608115f87f1b7193e32e77bf7a5 }


condition:
	$a0
}