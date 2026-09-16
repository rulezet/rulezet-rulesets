rule Win_Spyware_Banker_2463
{
strings:
	$a0 = { 3293d081dee0cade47a3ca03acdbc69240f41e0d4dfea2cdc25276a5f6f47abfa0688bc1264f32cc8dff5c286391d91be783d7520a2494dd05f2532aefa6c255705dd2c4943621d14d01 }


condition:
	$a0
}