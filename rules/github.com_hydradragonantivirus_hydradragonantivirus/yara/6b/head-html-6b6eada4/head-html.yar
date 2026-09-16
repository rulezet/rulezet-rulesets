rule head_html {
  condition:
    uint32be(0) == 0x3c68746d
}