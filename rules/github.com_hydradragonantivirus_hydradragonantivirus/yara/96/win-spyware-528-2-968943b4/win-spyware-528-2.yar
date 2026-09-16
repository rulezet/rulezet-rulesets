rule Win_Spyware_528_2
{
strings:
	$a0 = { 262be44c62f834e39861b904e76caf3bec1e8243d2a049697a066007ccf8c4cf4cb4c08cdec2ea16a9150f745465a6bad67ea410cb01ab5b9784dccccabe08beb9b1a94144c558df920d21 }


condition:
	$a0
}