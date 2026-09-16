rule TTP_XOR_MULT_DOSStub_7d21 {
  strings:
    $key_7d21 = { 29 49 [2] 5d 51 [2] 1a 53 [2] 5d 42 [2] 13 4e [2] 1f 44 [2] 08 4f [2] 13 01 [2] 2e }

  condition:
    any of them
}