rule head_doc {
  condition:
    uint32be(0) == 0xd0cf11e0
}