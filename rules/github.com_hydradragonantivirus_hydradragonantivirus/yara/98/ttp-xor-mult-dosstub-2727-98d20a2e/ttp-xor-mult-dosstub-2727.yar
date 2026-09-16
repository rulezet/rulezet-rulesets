rule TTP_XOR_MULT_DOSStub_2727 {
  strings:
    $key_2727 = { 73 4f [2] 07 57 [2] 40 55 [2] 07 44 [2] 49 48 [2] 45 42 [2] 52 49 [2] 49 07 [2] 74 }

  condition:
    any of them
}