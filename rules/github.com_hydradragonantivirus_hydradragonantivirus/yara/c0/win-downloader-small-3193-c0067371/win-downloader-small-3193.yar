rule Win_Downloader_Small_3193
{
strings:
	$a0 = { 4fa44b01a96c7e826cf9ee31a676609f565366a6d9934c0ff47264f1524e294ad2f36af25dab9dc7d5f1e6f95f7c6e7da9f3ef6c268259b765ff929070b30a2fa486b31c2103 }


condition:
	$a0
}