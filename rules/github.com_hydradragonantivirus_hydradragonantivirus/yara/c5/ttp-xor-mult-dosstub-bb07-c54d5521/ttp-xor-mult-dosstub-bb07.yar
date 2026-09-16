rule TTP_XOR_MULT_DOSStub_bb07 {
  strings:
    $key_bb07 = { ef 6f [2] 9b 77 [2] dc 75 [2] 9b 64 [2] d5 68 [2] d9 62 [2] ce 69 [2] d5 27 [2] e8 }

  condition:
    any of them
}