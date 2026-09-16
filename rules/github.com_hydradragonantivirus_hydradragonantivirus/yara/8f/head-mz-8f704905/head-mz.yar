rule head_mz {
  condition:
    uint16be(0) == 0x4d5a
}