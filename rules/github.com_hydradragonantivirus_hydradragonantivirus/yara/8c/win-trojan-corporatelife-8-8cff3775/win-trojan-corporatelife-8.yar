rule Win_Trojan_CorporateLife_8
{
strings:
	$a0 = { 4606904646460efbfb4efb1ffbfbbd2707904e90bf3e01908035a290904e4746464d75f4464646fbfb4e90fb4e }


condition:
	$a0
}