rule Win_Trojan_Vgen_9
{
strings:
	$a0 = { 0300b8ffa02bdbcd210681fbffa07458b82135cd21899e9e028c86a0028cd8488ec026803e00005a757c26832e }


condition:
	$a0
}