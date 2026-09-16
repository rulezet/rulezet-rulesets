rule Win_Trojan_WereWolf_1
{
strings:
	$a0 = { feb430cd213c06770d3c037209b20db88702cd21733bbf00ff33fdbe0000572e803e97054575238cc00510002e01 }


condition:
	$a0
}