rule TTP_XOR_MULT_DOSStub_6e37 {
  strings:
    $key_6e37 = { 3a 5f [2] 4e 47 [2] 09 45 [2] 4e 54 [2] 00 58 [2] 0c 52 [2] 1b 59 [2] 00 17 [2] 3d }

  condition:
    any of them
}