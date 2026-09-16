rule Win_Dropper_Agent_36754
{
strings:
	$a0 = { 60be6e2640008dbeebafffff5783cdffeb109090909090908a064688074701db7507615051740583c809eb0231c0f91b }


condition:
	$a0
}