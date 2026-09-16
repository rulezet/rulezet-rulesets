rule Win_Trojan_Bancos_1758
{
strings:
	$a0 = { 3279f8aee56a8669fc86a3ebb65d5b6ec85dc4d973d012a55109afb7b3b797871c7db776daade577a96e3b4ce6830d5f82818e5d54430ed48cf890aa58a3325d40767ad8a9fe }


condition:
	$a0
}