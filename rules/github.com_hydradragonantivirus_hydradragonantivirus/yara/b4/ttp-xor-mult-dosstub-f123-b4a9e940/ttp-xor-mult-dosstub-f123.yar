rule TTP_XOR_MULT_DOSStub_f123 {
  strings:
    $key_f123 = { a5 4b [2] d1 53 [2] 96 51 [2] d1 40 [2] 9f 4c [2] 93 46 [2] 84 4d [2] 9f 03 [2] a2 }

  condition:
    any of them
}