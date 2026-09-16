rule TTP_XOR_MULT_DOSStub_b779 {
  strings:
    $key_b779 = { e3 11 [2] 97 09 [2] d0 0b [2] 97 1a [2] d9 16 [2] d5 1c [2] c2 17 [2] d9 59 [2] e4 }

  condition:
    any of them
}