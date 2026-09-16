rule TTP_XOR_MULT_DOSStub_0021 {
  strings:
    $key_0021 = { 54 49 [2] 20 51 [2] 67 53 [2] 20 42 [2] 6e 4e [2] 62 44 [2] 75 4f [2] 6e 01 [2] 53 }

  condition:
    any of them
}