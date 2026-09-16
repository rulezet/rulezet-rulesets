rule TTP_XOR_MULT_DOSStub_b268 {
  strings:
    $key_b268 = { e6 00 [2] 92 18 [2] d5 1a [2] 92 0b [2] dc 07 [2] d0 0d [2] c7 06 [2] dc 48 [2] e1 }

  condition:
    any of them
}