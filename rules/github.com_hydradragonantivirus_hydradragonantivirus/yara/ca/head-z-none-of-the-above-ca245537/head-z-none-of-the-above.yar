rule head_z_none_of_the_above {
  condition:
    uint16be(0) == 0x1f8b
    and uint16be(0) == 0x377a
    and uint16be(0) != 0x4d5a
    and uint16be(0) != 0x504b
    and uint32be(0) != 0x3c68746d
    and uint32be(0) != 0x47494638
    and uint32be(0) != 0x4b57414a
    and uint32be(0) != 0x4d534346
    and uint32be(0) != 0x52617221
    and uint32be(0) != 0x535a4444
    and uint32be(0) != 0x7b5c7274
    and uint32be(0) != 0x7f454c46
    and uint32be(0) != 0x89504e47
    and uint32be(0) != 0xd0cf11e0
    and uint32be(0) != 0xffd8ffe0
    and uint32be(0) != 0x6465780a
    and uint32(0) != 0xfeedface
    and uint32(0) != 0xcefaedfe
    and uint32(0) != 0xfeedfacf
    and uint32(0) != 0xcffaedfe
    and uint32(0) != 0xcafebabe
    and uint32(0) != 0xbebafeca
}