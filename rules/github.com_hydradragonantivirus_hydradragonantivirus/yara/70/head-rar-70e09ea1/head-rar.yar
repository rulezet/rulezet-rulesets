rule head_rar {
  condition:
    uint32be(0) == 0x52617221
}