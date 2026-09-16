rule Win_Spyware_Banker_3381
{
strings:
	$a0 = { 4b1e25e58e8b4e497c5dc6ad8ee22cd8dc5d753168250e742ce36e9adbb9efdb5c547bf6717bbea6455712aac2a1aa89583d0aebe5e663893f9a684bfa0fe87a00c2a95f91f2 }


condition:
	$a0
}