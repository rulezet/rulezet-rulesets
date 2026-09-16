rule Win_Spyware_Banker_2710
{
strings:
	$a0 = { 4a7eb44296b0cdf4e140d1a01ebde5f1a88786180ba8fbc8fc5eba4aa864b67c9ad0f507317c344eccd262764d33d1bf68b21324d0d91aa7e76907d98bf94b60d4854d0ee0339e255f7b7199a3ca }


condition:
	$a0
}