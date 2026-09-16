rule TTP_XOR_MULT_DOSStub_f207 {
  strings:
    $key_f207 = { a6 6f [2] d2 77 [2] 95 75 [2] d2 64 [2] 9c 68 [2] 90 62 [2] 87 69 [2] 9c 27 [2] a1 }

  condition:
    any of them
}