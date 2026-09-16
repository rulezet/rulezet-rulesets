rule TTP_XOR_MULT_DOSStub_2725 {
  strings:
    $key_2725 = { 73 4d [2] 07 55 [2] 40 57 [2] 07 46 [2] 49 4a [2] 45 40 [2] 52 4b [2] 49 05 [2] 74 }

  condition:
    any of them
}