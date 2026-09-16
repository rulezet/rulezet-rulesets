rule TTP_XOR_MULT_DOSStub_01ea {
  strings:
    $key_01ea = { 55 82 [2] 21 9a [2] 66 98 [2] 21 89 [2] 6f 85 [2] 63 8f [2] 74 84 [2] 6f ca [2] 52 }

  condition:
    any of them
}