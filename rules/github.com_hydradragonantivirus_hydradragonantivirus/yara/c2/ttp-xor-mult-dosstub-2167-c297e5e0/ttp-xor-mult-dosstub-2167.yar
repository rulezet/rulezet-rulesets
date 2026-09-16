rule TTP_XOR_MULT_DOSStub_2167 {
  strings:
    $key_2167 = { 75 0f [2] 01 17 [2] 46 15 [2] 01 04 [2] 4f 08 [2] 43 02 [2] 54 09 [2] 4f 47 [2] 72 }

  condition:
    any of them
}