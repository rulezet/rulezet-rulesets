rule head_pkzip {
  condition:
    uint16be(0) == 0x504b
}