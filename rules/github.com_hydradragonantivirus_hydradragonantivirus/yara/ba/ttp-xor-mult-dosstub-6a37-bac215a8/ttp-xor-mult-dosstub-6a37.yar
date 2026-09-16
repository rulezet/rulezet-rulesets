rule TTP_XOR_MULT_DOSStub_6a37 {
  strings:
    $key_6a37 = { 3e 5f [2] 4a 47 [2] 0d 45 [2] 4a 54 [2] 04 58 [2] 08 52 [2] 1f 59 [2] 04 17 [2] 39 }

  condition:
    any of them
}