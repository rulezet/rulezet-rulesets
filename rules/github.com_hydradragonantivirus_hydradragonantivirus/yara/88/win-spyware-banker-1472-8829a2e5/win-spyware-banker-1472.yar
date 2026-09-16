rule Win_Spyware_Banker_1472
{
strings:
	$a0 = { 6ae2030062545ae5ab5030f6811dea3e6584568b8468cd7abe581ce71a7d5bff8270fa99a4daeb57e1263b7b9a4333a3c8533b9f4c4b65e0ed2df3fd4fedc47deb4b94f6 }


condition:
	$a0
}