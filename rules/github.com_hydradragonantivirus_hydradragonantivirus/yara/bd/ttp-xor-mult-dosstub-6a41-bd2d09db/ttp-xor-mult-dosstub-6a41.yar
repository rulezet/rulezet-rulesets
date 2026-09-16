rule TTP_XOR_MULT_DOSStub_6a41 {
  strings:
    $key_6a41 = { 3e 29 [2] 4a 31 [2] 0d 33 [2] 4a 22 [2] 04 2e [2] 08 24 [2] 1f 2f [2] 04 61 [2] 39 }

  condition:
    any of them
}