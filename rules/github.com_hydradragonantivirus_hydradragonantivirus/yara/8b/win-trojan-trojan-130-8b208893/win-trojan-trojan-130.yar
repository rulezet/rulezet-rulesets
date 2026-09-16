rule Win_Trojan_Trojan_130
{
strings:
	$a0 = { 02000000b42acd2180fa0d7471fc5bb8aad5cd213d032a744c8bc440b104d3e8408cd203c28cda4a8ec233ffb92c008b55022bd13bd0722dfa26294d038955 }


condition:
	$a0
}