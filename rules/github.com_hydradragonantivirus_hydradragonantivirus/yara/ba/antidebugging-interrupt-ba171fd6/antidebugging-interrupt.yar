rule AntiDebugging_Interrupt {
  condition:
        uint32(0) == 0x00646120 and uint32(4) == 0x00646120 and
        (uint8(8) == 0xCC or uint8(8) == 0xF1 or uint8(8) == 0xCC)
}