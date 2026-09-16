rule Win_Trojan_SdBot_3673
{
strings:
	$a0 = { eab4b64f05075afabc2009983b9e6b8794e1a62bee7aadf5f401b7f57c237670fb585b24ffe48aa24be50b1faaf9a7861720155828d15faf3a54eb8b73d15ba7d70b3472fea3b32dd1ab470d99e6 }


condition:
	$a0
}