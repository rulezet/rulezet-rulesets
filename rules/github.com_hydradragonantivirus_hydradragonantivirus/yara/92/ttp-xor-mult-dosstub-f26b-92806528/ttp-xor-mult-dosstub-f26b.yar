rule TTP_XOR_MULT_DOSStub_f26b {
  strings:
    $key_f26b = { a6 03 [2] d2 1b [2] 95 19 [2] d2 08 [2] 9c 04 [2] 90 0e [2] 87 05 [2] 9c 4b [2] a1 }

  condition:
    any of them
}