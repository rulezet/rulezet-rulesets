rule Win_Spyware_Banker_3452
{
strings:
	$a0 = { 50a895a7abf4d0f1efa81cc1e25dc36b89a5ba52c1fd01a646aa296a2c0d8229980f8a50421cc26b3f881a8782ffc3ecce7ca040559bb13abcbf422b6f5fea18abe37db0b0d929a3e073432511d2c484 }


condition:
	$a0
}