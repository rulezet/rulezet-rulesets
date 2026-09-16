rule Win_Trojan_Reveton_2
{
strings:
	$a0 = { 4a3a5c57696e33323a52657665746f6e2d5859205b54726a5d2e706462 }


condition:
	$a0
}