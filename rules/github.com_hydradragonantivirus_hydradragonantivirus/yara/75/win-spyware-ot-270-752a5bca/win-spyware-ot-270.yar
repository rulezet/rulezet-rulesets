rule Win_Spyware_ot_270
{
strings:
	$a0 = { 8fc9cc3adbd6021ad4073bbd3e7fbfe27aa22afc380c85a43fc5a56e52bfbdb031273e194da379e73f7fc5fc7ad6aa31b66f8330b8724ad0327127e8bc2ae5c799721dbf9dccad0d1d88ae5520f2624c6ee2c6e1ab }


condition:
	$a0
}