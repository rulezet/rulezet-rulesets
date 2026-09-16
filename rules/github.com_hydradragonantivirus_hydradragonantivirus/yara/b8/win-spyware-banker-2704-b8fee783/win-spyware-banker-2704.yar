rule Win_Spyware_Banker_2704
{
strings:
	$a0 = { 30cfd4648c7c079cbee8f3f70e6a9fc820c315baaab1d29a110020728169745c642218e6afb586492bf68ce5624406ed2c4f0fb3822ed2b862e43e02eff082fab86f23bfebcad2dff91fd5395701 }


condition:
	$a0
}