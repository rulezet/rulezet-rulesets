rule Win_Spyware_Banker_1307
{
strings:
	$a0 = { b775278f2b39d5a4ce15e8a976133129da53c276265124fdaea76500dbc3fbe438c0d55b6373603c2e2c552be184f27da957ac9e3fdd06c6c2a277843cea6d024254e93d }


condition:
	$a0
}