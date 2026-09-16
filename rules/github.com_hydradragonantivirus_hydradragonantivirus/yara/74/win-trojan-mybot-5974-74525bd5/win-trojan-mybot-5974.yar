rule Win_Trojan_Mybot_5974
{
strings:
	$a0 = { 159a7601bfb5590ab7b076ff04a2470938767d28ffae0adc14f7de0a338bde3b7fde7cab776d53852cb8ffc228dbec3008629dff881e861480b3b910f548c4e18b2cd5e80b7511ff45456b9ad7d04b9e }


condition:
	$a0
}