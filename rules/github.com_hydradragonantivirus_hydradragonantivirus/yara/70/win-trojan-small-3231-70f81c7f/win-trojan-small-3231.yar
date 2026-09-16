rule Win_Trojan_Small_3231
{
strings:
	$a0 = { d1d3a7d309cd8b3316fc6f9315f46f9b46ed4b338de20bc109d4b4bce1d3af26393d9757913c9f57a5009d99381a4b9d8d198f9d8d59b5331af46fabf7af9b9d8dae60179eef4bb84dbfcfcf8eaf4bbe9a33 }


condition:
	$a0
}