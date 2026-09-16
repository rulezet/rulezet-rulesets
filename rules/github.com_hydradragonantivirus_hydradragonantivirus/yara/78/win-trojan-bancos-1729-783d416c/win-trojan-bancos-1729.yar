rule Win_Trojan_Bancos_1729
{
strings:
	$a0 = { d7327161221acf10bb9f37324418f368089fdcc2c24154827e3823bc676b4cf431274b12c4bb71d2fc5ceb77b1efe8ba659dfd1777a7548fc9825c6234ee90f6cfef46c10fce }


condition:
	$a0
}