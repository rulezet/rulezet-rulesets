rule TTP_XOR_MULT_DOSStub_8e0b {
  strings:
    $key_8e0b = { da 63 [2] ae 7b [2] e9 79 [2] ae 68 [2] e0 64 [2] ec 6e [2] fb 65 [2] e0 2b [2] dd }

  condition:
    any of them
}