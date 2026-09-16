rule TTP_XOR_MULT_DOSStub_7221 {
  strings:
    $key_7221 = { 26 49 [2] 52 51 [2] 15 53 [2] 52 42 [2] 1c 4e [2] 10 44 [2] 07 4f [2] 1c 01 [2] 21 }

  condition:
    any of them
}