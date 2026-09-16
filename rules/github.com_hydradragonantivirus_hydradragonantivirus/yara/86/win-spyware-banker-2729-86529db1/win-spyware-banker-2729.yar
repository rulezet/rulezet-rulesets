rule Win_Spyware_Banker_2729
{
strings:
	$a0 = { d256a32e593054d0d8c8ec73abb066a14bc7db3b236f3dd570501fcc608a5b66180eccaaff8f3c1a255ab62cffa252b203c72b003bc46eff9e4701827e7b181cb8ad7d822b2def7702cdb2341151 }


condition:
	$a0
}