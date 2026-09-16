rule TTP_XOR_MULT_DOSStub_2171 {
  strings:
    $key_2171 = { 75 19 [2] 01 01 [2] 46 03 [2] 01 12 [2] 4f 1e [2] 43 14 [2] 54 1f [2] 4f 51 [2] 72 }

  condition:
    any of them
}