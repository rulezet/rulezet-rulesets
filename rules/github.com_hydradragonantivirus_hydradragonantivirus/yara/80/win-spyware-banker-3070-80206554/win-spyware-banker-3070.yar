rule Win_Spyware_Banker_3070
{
strings:
	$a0 = { 11f1d1d97ca69e97f7d77448a30872ea48c18b91c5a57fa00ba44fc8c39f0832dce654db363ebf074c274805c3f38e701ecd335dcaed23a846f32b20eeab }


condition:
	$a0
}