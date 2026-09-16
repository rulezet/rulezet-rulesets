rule Win_Trojan_Lokjaw_3
{
strings:
	$a0 = { bac601bbd301b8004bcd218bd88cc88ed0bc????538ed88ec0b41aba8000cd21e83400e89a00e8a302e8fe02 }


condition:
	$a0
}