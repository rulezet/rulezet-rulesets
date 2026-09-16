rule head_rtf {
  condition:
    uint32be(0) == 0x7b5c7274
}