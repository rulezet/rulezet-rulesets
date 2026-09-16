rule head_png {
  condition:
    uint32be(0) == 0x89504e47
}