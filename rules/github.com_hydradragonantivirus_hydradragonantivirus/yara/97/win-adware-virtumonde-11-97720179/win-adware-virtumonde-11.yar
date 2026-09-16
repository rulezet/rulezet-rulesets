rule Win_Adware_Virtumonde_11
{
strings:
	$a0 = { 6398cf4ee6eda8717e9fd5435f1a2f274a1bd8d8bac38dc6de3ecbc21dfc3aad8205308bd12352914a2db53a2388f1db1fd8fb6398fe201a06ad180e48c15c82a54a8070043b93c4f81e3ddcc87883ec }


condition:
	$a0
}