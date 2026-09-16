rule Win_Trojan_Kode4_9
{
strings:
	$a0 = { cd213d0101744eb44eba5a01cd21b443b000ba9e00cd21b443b00181e1fe00cd21b8013dba9e00cd218bd8b457b000cd215152ba0001b181b440cd215a }


condition:
	$a0
}