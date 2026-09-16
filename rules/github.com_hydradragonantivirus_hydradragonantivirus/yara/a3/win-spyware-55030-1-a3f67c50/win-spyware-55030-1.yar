rule Win_Spyware_55030_1
{
strings:
	$a0 = { 30ffffff75727265c78534ffffff6e745665c78538ffffff7273696fc7853cffffff6e5c5368c78540ffffff656c6c53c78544ffffff65727669c78548ffffff63654f62c785 }


condition:
	$a0
}