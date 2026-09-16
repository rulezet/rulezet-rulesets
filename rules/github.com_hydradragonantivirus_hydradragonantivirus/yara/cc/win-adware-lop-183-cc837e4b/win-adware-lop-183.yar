rule Win_Adware_Lop_183
{
strings:
	$a0 = { 21c78eb09c12389e942c9b1e0b0b9c096d45bacae0bf743e944883b25e88228963bba5113f2affe317d245f6a39c7a1df97a94c475135c285f643436 }


condition:
	$a0
}