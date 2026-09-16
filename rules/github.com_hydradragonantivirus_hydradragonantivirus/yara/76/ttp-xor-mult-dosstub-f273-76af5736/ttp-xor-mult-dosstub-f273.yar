rule TTP_XOR_MULT_DOSStub_f273 {
  strings:
    $key_f273 = { a6 1b [2] d2 03 [2] 95 01 [2] d2 10 [2] 9c 1c [2] 90 16 [2] 87 1d [2] 9c 53 [2] a1 }

  condition:
    any of them
}