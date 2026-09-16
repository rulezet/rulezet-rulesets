rule Win_Trojan_VGEN_82
{
strings:
	$a0 = { 5e81ee0d018cddb83254cd213d07107703e96d008cd8488ed8803e00005a740b8b1e030001d8408ed8ebee8ed8 }


condition:
	$a0
}