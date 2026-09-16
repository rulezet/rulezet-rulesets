rule Win_Trojan_Agent_33537
{
strings:
	$a0 = { aa3fa9bd5f340cf66134b3d60c605385f17ea3250c61caee65d98a2eafe031fd3b3ef7613e8f603fff3e65a5e6e88172f7cd3a9f1a98251cc9e9bf0008ee4fd669839646f82f3c628a4f95dbc522770f0a4d }


condition:
	$a0
}