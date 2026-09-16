rule TTP_XOR_MULT_DOSStub_b369 {
  strings:
    $key_b369 = { e7 01 [2] 93 19 [2] d4 1b [2] 93 0a [2] dd 06 [2] d1 0c [2] c6 07 [2] dd 49 [2] e0 }

  condition:
    any of them
}