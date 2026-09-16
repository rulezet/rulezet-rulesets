rule TTP_XOR_MULT_DOSStub_b26e {
  strings:
    $key_b26e = { e6 06 [2] 92 1e [2] d5 1c [2] 92 0d [2] dc 01 [2] d0 0b [2] c7 00 [2] dc 4e [2] e1 }

  condition:
    any of them
}