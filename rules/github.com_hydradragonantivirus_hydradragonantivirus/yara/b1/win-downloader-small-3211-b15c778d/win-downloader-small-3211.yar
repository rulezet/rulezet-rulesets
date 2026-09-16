rule Win_Downloader_Small_3211
{
strings:
	$a0 = { a6c19745ffd699a789c4c9b38bb45f3846064fef50d4073ef6d74fef2e06a101cdeecf4b0ca153d3cfe0500a26864f6f08e2aafac4e547ef2606af0cd8ccb2b02606842731cf }


condition:
	$a0
}