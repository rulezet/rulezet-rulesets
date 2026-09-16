rule TTP_XOR_MULT_DOSStub_3b27 {
  strings:
    $key_3b27 = { 6f 4f [2] 1b 57 [2] 5c 55 [2] 1b 44 [2] 55 48 [2] 59 42 [2] 4e 49 [2] 55 07 [2] 68 }

  condition:
    any of them
}