rule IsELF64: ELFCheck {
  condition:
        uint32(0) == 0x464C457F and
    uint8(0x4) == 0x02
}