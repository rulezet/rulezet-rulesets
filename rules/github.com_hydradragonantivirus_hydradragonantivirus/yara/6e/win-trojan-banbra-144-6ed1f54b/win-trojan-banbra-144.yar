rule Win_Trojan_Banbra_144
{
strings:
	$a0 = { 7e0f968aa7fc1f32950d04bfaa9f973edd062aa96cf3dd1a8043eccdd6336883da2afef8abef4d4922cf078e934d4374c79acac891bfb29b57073a08597ffb8dea595fa8a617a321fd589a60b0d654da }


condition:
	$a0
}