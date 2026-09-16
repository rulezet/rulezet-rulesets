rule Win_Spyware_Banker_2685
{
strings:
	$a0 = { c0d9c49afb0d6a553d319432ab9f7feab0600c7ba69896066ff5f391ed559565d9b12ad1d0219c703c70a2344678dccd27389d0206546ba999b5cca2f674de0b21389ddba8b45f66dca8fce871ef }


condition:
	$a0
}