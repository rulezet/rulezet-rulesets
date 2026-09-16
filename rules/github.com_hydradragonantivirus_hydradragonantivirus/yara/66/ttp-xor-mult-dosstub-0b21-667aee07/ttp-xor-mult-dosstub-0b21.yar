rule TTP_XOR_MULT_DOSStub_0b21 {
  strings:
    $key_0b21 = { 5f 49 [2] 2b 51 [2] 6c 53 [2] 2b 42 [2] 65 4e [2] 69 44 [2] 7e 4f [2] 65 01 [2] 58 }

  condition:
    any of them
}