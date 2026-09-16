rule Zip_Crypto__32_big_AND_
{
strings:
	$a0 = { 08088405[0-20]12345678[0-20]23456789[0-20]34567890 }

condition:
	$a0
}