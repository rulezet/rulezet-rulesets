rule TTP_XOR_MULT_DOSStub_b728 {
  strings:
    $key_b728 = { e3 40 [2] 97 58 [2] d0 5a [2] 97 4b [2] d9 47 [2] d5 4d [2] c2 46 [2] d9 08 [2] e4 }

  condition:
    any of them
}