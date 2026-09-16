rule Win_Downloader_Swizzor_284
{
strings:
	$a0 = { 01f842e7fb255219c7146a07e69df206303c70b409d79007b677940da888dc05be76d8ae52f867bb7bfecdda7d78bc7a }


condition:
	$a0
}