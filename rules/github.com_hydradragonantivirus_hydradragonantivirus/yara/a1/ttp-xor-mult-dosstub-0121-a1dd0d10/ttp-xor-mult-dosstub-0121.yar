rule TTP_XOR_MULT_DOSStub_0121 {
  strings:
    $key_0121 = { 55 49 [2] 21 51 [2] 66 53 [2] 21 42 [2] 6f 4e [2] 63 44 [2] 74 4f [2] 6f 01 [2] 52 }

  condition:
    any of them
}