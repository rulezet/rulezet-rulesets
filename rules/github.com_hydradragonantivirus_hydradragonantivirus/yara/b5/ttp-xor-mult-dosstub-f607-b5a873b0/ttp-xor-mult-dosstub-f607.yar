rule TTP_XOR_MULT_DOSStub_f607 {
  strings:
    $key_f607 = { a2 6f [2] d6 77 [2] 91 75 [2] d6 64 [2] 98 68 [2] 94 62 [2] 83 69 [2] 98 27 [2] a5 }

  condition:
    any of them
}