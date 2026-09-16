rule Win_Downloader_Agent_35052
{
strings:
	$a0 = { 0333849f38d4cfbc16421bfe7c0d81097b27f0b6773bd96aed9f6aed4d0a96bb49afc8fe8bc217371d253bfec938a08d1f23 }


condition:
	$a0
}