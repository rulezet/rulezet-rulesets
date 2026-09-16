rule Win_Adware_Lop_205
{
strings:
	$a0 = { 37e5b6af34bf971e8248d1639e85cefec8aa22156484cb1d2d1d506ded001627745987607250cee8954b20d57603bf63eff0de4fa08e48fd531835ff }


condition:
	$a0
}