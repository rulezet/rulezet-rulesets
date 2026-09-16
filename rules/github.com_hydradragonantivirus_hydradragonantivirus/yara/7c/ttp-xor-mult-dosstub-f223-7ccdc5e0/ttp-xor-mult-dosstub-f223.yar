rule TTP_XOR_MULT_DOSStub_f223 {
  strings:
    $key_f223 = { a6 4b [2] d2 53 [2] 95 51 [2] d2 40 [2] 9c 4c [2] 90 46 [2] 87 4d [2] 9c 03 [2] a1 }

  condition:
    any of them
}