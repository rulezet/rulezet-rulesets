rule TTP_XOR_MULT_DOSStub_6a36 {
  strings:
    $key_6a36 = { 3e 5e [2] 4a 46 [2] 0d 44 [2] 4a 55 [2] 04 59 [2] 08 53 [2] 1f 58 [2] 04 16 [2] 39 }

  condition:
    any of them
}