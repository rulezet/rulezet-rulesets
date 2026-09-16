rule Win_Downloader_Banload_839
{
strings:
	$a0 = { fa14787a7cb1cdb7397093ef671c8c0d0d58a3e5400cfc8b61a57bc095d5e5b2ee4beb3f7e920ae124b88dc6c38c13994e7e9c914c48259341802ca17e2c7371feb7bbaed2e2bdd5 }


condition:
	$a0
}