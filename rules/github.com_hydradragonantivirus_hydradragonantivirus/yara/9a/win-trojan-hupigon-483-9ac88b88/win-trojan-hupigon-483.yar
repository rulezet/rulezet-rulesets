rule Win_Trojan_Hupigon_483
{
strings:
	$a0 = { 372d62ea6c1ce6946d27c7f85d52404471a821a2c6433d0020943cca403a45af54d2323555f4175a1e0aefb2c202865c1efc7cebf8daa60c3583b078469843f9b0ecfaafadc6468ba115ad9308ef }


condition:
	$a0
}