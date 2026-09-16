rule TTP_XOR_MULT_DOSStub_f274 {
  strings:
    $key_f274 = { a6 1c [2] d2 04 [2] 95 06 [2] d2 17 [2] 9c 1b [2] 90 11 [2] 87 1a [2] 9c 54 [2] a1 }

  condition:
    any of them
}