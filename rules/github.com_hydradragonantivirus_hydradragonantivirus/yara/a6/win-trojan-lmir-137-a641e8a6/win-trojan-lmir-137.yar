rule Win_Trojan_Lmir_137
{
strings:
	$a0 = { 5c9871c9f49e5faeaa88d296a3cb82b1a5c352fcff9c85c5e0fd43cc7d2f5461a03594adea5f53c73b5bb0d39b888b83e973cd056795eeace0fd9dbd7bf94bbe }


condition:
	$a0
}