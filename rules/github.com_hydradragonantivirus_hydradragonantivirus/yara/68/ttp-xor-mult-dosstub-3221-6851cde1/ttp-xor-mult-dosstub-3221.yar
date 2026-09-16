rule TTP_XOR_MULT_DOSStub_3221 {
  strings:
    $key_3221 = { 66 49 [2] 12 51 [2] 55 53 [2] 12 42 [2] 5c 4e [2] 50 44 [2] 47 4f [2] 5c 01 [2] 61 }

  condition:
    any of them
}