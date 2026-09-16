rule PELock106 : Bartosz Wojcik
{
	meta:
		author="_pusher_"
		date = "2015-12"
	condition:				
		(uint32(uint32(0x3C)+0xF4) == 0x00001000) and
		(uint32(uint32(0x3C)+0x84) == 0x0000005C) and				(uint32(uint32(0x3C)+0x80)+uint32(uint32(0x3C)+0x84) == uint32(uint32(0x3C)+0x28)) 		
}