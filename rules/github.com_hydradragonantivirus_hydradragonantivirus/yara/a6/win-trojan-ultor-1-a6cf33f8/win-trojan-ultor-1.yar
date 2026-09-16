rule Win_Trojan_Ultor_1
{
strings:
	$a0 = { e7834c2e94833a5c44b2832e94833cb2a8832e9434b22c39a8833a1c2414554239e8420c55e84239e8d4543aa8833adc04e48a0bac83fccc0eeaa00ef4c4a01b }


condition:
	$a0
}