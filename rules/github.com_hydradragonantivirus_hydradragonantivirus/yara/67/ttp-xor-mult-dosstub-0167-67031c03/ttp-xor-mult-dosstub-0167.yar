rule TTP_XOR_MULT_DOSStub_0167 {
  strings:
    $key_0167 = { 55 0f [2] 21 17 [2] 66 15 [2] 21 04 [2] 6f 08 [2] 63 02 [2] 74 09 [2] 6f 47 [2] 52 }

  condition:
    any of them
}